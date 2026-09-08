//! Domain placement for loaded modules.
//!
//! Every NARF module declares a `target_domain=<name>` in its
//! manifest. The loader maps the module's text + rodata into that
//! domain's PKS-protected region (read-execute from in-domain,
//! no-access from out-of-domain) and the data + bss into the same
//! domain's RW region.
//!
//! Concretely, the kernel maintains a `name -> DomainId` table that
//! drivers populate at boot. The loader consults the table to pick
//! the runtime DomainId; if the module asks for a domain that doesn't
//! exist, load fails.
//!
//! This is a NARF-only mechanism — Linux has no equivalent because
//! it has no driver isolation.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

/// Errors from domain resolution.
#[derive(Debug, PartialEq, Eq)]
pub enum DomainError {
    /// `target_domain` references an unregistered name.
    Unknown(String),
}

/// One registered driver domain. The kernel boot path registers all
/// driver-domain names; modules subsequently target one of these.
#[derive(Clone, Debug)]
struct DomainEntry {
    name: String,
    id: DomainId,
}

static REGISTRY: IrqSafeSpinLock<Vec<DomainEntry>> = IrqSafeSpinLock::new(Vec::new());

/// Register a driver-domain name -> id mapping. Idempotent on name.
pub fn register_domain(name: &str, id: DomainId) {
    let mut g = REGISTRY.lock();
    if let Some(e) = g.iter_mut().find(|e| e.name == name) {
        e.id = id;
    } else {
        g.push(DomainEntry {
            name: name.to_string(),
            id,
        });
    }
}

/// Look up a domain by name. None if not registered.
pub fn lookup_domain(name: &str) -> Option<DomainId> {
    let g = REGISTRY.lock();
    g.iter().find(|e| e.name == name).map(|e| e.id)
}

/// Number of registered domains. For tests.
pub fn count() -> usize {
    REGISTRY.lock().len()
}

/// Reset registry (test helper).
#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
}

/// Pre-populate with the standard driver-domain slots from
/// `narf_lib::id::DomainId::DRIVER_0..=DRIVER_4`, plus the BPF runtime's
/// own domain. Bring-up code can also pass concrete names ("net",
/// "block", "graphics") so module authors don't have to memorise
/// numbers. Idempotent.
pub fn install_standard_domains() {
    register_domain("driver0", DomainId::DRIVER_0);
    register_domain("driver1", DomainId::DRIVER_1);
    register_domain("driver2", DomainId::DRIVER_2);
    register_domain("driver3", DomainId::DRIVER_3);
    register_domain("driver4", DomainId::DRIVER_4);
    register_domain("bpf", DomainId::BPF);
    register_domain("scratch", DomainId::SCRATCH);
    // Named aliases for the common driver subsystems.
    register_domain("net", DomainId::DRIVER_0);
    register_domain("block", DomainId::DRIVER_1);
    register_domain("graphics", DomainId::DRIVER_2);
    register_domain("input", DomainId::DRIVER_3);
    register_domain("crypto", DomainId::DRIVER_4);
}

/// Resolve a domain name (from a manifest) to a DomainId, returning
/// `DomainError::Unknown` if it isn't registered. The empty string
/// (no `target_domain` declared) falls back to `SCRATCH`.
pub fn resolve(name: &str) -> Result<DomainId, DomainError> {
    if name.is_empty() {
        return Ok(DomainId::SCRATCH);
    }
    lookup_domain(name).ok_or_else(|| DomainError::Unknown(name.to_string()))
}

// ── Running module code inside its domain ──────────────────────────────

/// A narrowed PKS rights state, to be handed back to [`exit`].
///
/// Opaque and arch-neutral: on x86_64 it carries the saved `IA32_PKRS`, and
/// on every other target it carries nothing, because no backend there tags
/// pages by domain yet.
#[derive(Debug)]
pub struct DomainScope {
    /// The domain this CPU was in before `enter`. Restored by `exit` rather
    /// than reset to FRAME, because scopes nest: a BPF program invoked from
    /// inside a module's `init()` opens a second one.
    prev_domain: u8,
    #[cfg(target_arch = "x86_64")]
    saved: narf_arch::x86_64::pks::SavedPkrs,
    /// `None` when MTE is absent, so `exit` does not write `SCTLR_EL1` back on
    /// a CPU where `enter` never touched it.
    #[cfg(target_arch = "aarch64")]
    saved: Option<narf_arch::aarch64::mte::SavedMteState>,
}

/// Enter `domain` — deny every PKS domain except the kernel's and this one.
///
/// Called around each entry into module code (`narf_module_init`,
/// `narf_module_exit`). While the scope is open a module can reach its own
/// image and the kernel, and faults on the other fourteen domains. That is
/// the isolation DESIGN.md §2 describes: a buggy module cannot corrupt
/// another driver's memory.
///
/// The kernel's domain deliberately stays reachable. A module that could not
/// call an exported function or read a kernel global could not do anything,
/// and closing that direction instead would mean an MSR write on every
/// crossing — worth measuring before it is anyone's default.
///
/// Dispatches to whichever x86 backend is live. `Pks::enter_domain` is the
/// `DomainPrimitive` impl, which switches `IA32_PKRS` under PKS and swaps to
/// the domain's PCID-tagged CR3 under PCID -- this used to call
/// `pks::enter_domain` directly and gate on `pks::is_active()` alone, so a
/// module on an AMD or pre-SPR Intel part ran with the pages still carrying
/// their protection key and nothing consulting it. `bpf::domain::enter` has
/// dispatched for both backends all along; this is the same call.
///
/// Still a no-op when neither backend can enforce -- no PKS and no usable
/// CR4.PCIDE, or another architecture. `enter_domain` itself declines in that
/// case, and the boot log says so.
pub fn enter(domain: DomainId) -> DomainScope {
    // Record the scope before narrowing anything. `current_domain()` is what
    // makes a per-domain decision possible further down -- a tagged heap
    // allocation has to know whose it is -- and it must be true for the whole
    // scope, including the part of `enter` that follows.
    let prev_domain = narf_arch::enter_domain_scope(domain.raw());
    #[cfg(target_arch = "x86_64")]
    {
        if narf_arch::x86_64::pks::is_active() || narf_arch::x86_64::pcid::is_active() {
            // SAFETY: one backend is live; both ids are 0..=15 (`DomainId` is
            // constructed from that range). Under PCID this swaps CR3 to the
            // domain's PML4 clone; under PKS it narrows IA32_PKRS.
            let saved = unsafe {
                <narf_arch::x86_64::Pks as narf_arch::DomainPrimitive>::enter_domain(
                    DomainId::FRAME.raw(),
                    domain.raw(),
                )
            };
            return DomainScope { prev_domain, saved };
        }
        // Inactive: capture the current value so `exit` restores exactly
        // what was there rather than assuming all-allow.
        DomainScope {
            prev_domain,
            saved: narf_arch::x86_64::pks::SavedPkrs(0),
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        use narf_arch::aarch64::{mte, Mte};
        use narf_arch::DomainPrimitive;
        if mte::supported() {
            // The image's pages are `ATTR_TAGGED` with the domain's tag in
            // every granule (`memory::module_text`), and the loader relocated
            // against `tagged_base()`, so the module's own accesses carry that
            // tag. Flipping TCF to Sync therefore makes a pointer into this
            // image derived from another domain fault -- the aarch64
            // equivalent of narrowing IA32_PKRS.
            //
            // Safe for everything else it touches: checks apply only to
            // `ATTR_TAGGED` pages, and the heap from `narf_kmalloc`, the
            // globals behind the four exported ABI functions, and its kernel
            // stack are all plain Normal.
            //
            // SAFETY: MTE is present; both ids are 0..=15.
            let saved = unsafe { Mte::enter_domain(DomainId::FRAME.raw(), domain.raw()) };
            return DomainScope {
                prev_domain,
                saved: Some(saved),
            };
        }
        DomainScope {
            prev_domain,
            saved: None,
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = domain;
        DomainScope { prev_domain }
    }
}

/// Leave a scope opened by [`enter`], restoring the previous rights.
///
/// Must run even when the module's entry point returned an error: leaving
/// PKRS narrowed would deny the rest of the kernel access to every domain
/// but two, and the fault would land arbitrarily far from here.
/// Bytes of dead stack erased when a module domain scope closes.
///
/// Covers the module's own frames to this depth; a module that recursed
/// deeper leaves residue below it. That is a coverage limit, not a
/// correctness one — the alternative is a low-water mark, which needs either
/// painting the stack (unreliable: CPL0 interrupts push into the same region)
/// or compiler instrumentation.
///
/// 8 KiB rather than the whole 32 KiB stack because the erase runs with
/// interrupts masked. `arch/specification/domain-stacks.md` measures ~1.75 us
/// here against ~6 us for a full stack; a module load can afford either, and
/// the interrupt-off window is what argues for the smaller.
const SCRUB_BYTES: usize = 8 * 1024;

/// Zero `len` bytes at `start` without making a call.
///
/// This is the whole reason the first attempt at scrub-on-exit was reverted.
/// Calling `write_bytes` pushes a return address at `SP - 8` on x86, which is
/// *inside* the region being erased, so memset zeroed its own return slot and
/// `ret` jumped to null — `#PF` with `rip = 0`. aarch64 survived only because
/// its return address goes in `LR`, a register, so the same code destroyed
/// itself on one architecture and not the other.
///
/// Both arms are `options(nostack)` and push nothing, so the erased region
/// cannot contain anything this function needs to return.
///
/// # Safety
/// `[start, start + len)` must be mapped, writable, and dead.
#[inline(always)]
unsafe fn erase_no_call(start: usize, len: usize) {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: `rep stosb` writes exactly `rcx` bytes from `rdi`. DF is clear
    // by ABI on entry, so the store direction is ascending.
    unsafe {
        core::arch::asm!(
            "rep stosb",
            inout("rdi") start => _,
            inout("rcx") len => _,
            inout("eax") 0u32 => _,
            options(nostack, preserves_flags),
        );
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: stores `n` doublewords ascending from `p`; `len` is rounded to
    // a multiple of 8 by the caller and SP is 16-byte aligned, so every store
    // is aligned and inside the range.
    unsafe {
        let words = len / 8;
        core::arch::asm!(
            "1:",
            "cbz {n}, 2f",
            "str xzr, [{p}], #8",
            "sub {n}, {n}, #1",
            "b 1b",
            "2:",
            p = inout(reg) start => _,
            n = inout(reg) words => _,
            options(nostack),
        );
    }
}

/// Erase the dead stack below `SP` after module code has returned.
///
/// Closes a module's frames outliving its scope: data left on the shared
/// kernel stack by one domain and read later by another. That is the concrete
/// gain per-domain stacks were considered for, and scrubbing buys it without
/// an SP switch, a guard page, an overflow stack, or any change to exception
/// entry — see `arch/specification/domain-stacks.md`.
///
/// Module scopes only. `bpf::domain::enter` wraps every program run, where an
/// erase of this size is the same order as the invocation it follows.
fn scrub_dead_stack() {
    // Read SP directly. `&0u8 as *const u8` is NOT a stack address: Rust
    // const-promotes the literal to a `'static`, so it yields `.rodata` in the
    // kernel image. An earlier version computed its extent from that and was
    // saved only by the containment check below.
    let here: usize;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: reading RSP into a register clobbers nothing.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) here, options(nomem, nostack, preserves_flags));
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: reading SP into a register clobbers nothing.
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) here, options(nomem, nostack, preserves_flags));
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        return;
    }

    let Some((bottom, top)) = narf_scheduler::stackful::current_stack_range() else {
        // Not on a stackful task — the executor's own stack, or early boot.
        // Bounds unknown, so erasing would be guessing where to stop.
        return;
    };
    // The reported range must actually contain the live SP. Clamping to a
    // bottom belonging to some other stack is not a clamp: it would authorise
    // writing 8 KiB below an address the bound says nothing about.
    if here <= bottom || here > top {
        return;
    }
    // Rounded to a multiple of 8 for the aarch64 store loop.
    let len = core::cmp::min(SCRUB_BYTES, here - bottom) & !7;
    if len == 0 {
        return;
    }
    let start = here - len;

    // Interrupts off. A handler taken at CPL0 pushes below `SP` — into
    // exactly the region being erased — so one landing mid-scrub would have
    // its live frame zeroed underneath it.
    let irqs = narf_arch::interrupts_enabled();
    if irqs {
        // SAFETY: re-enabled below on every path out.
        unsafe { narf_arch::disable_interrupts() };
    }
    // SAFETY: `[start, here)` is inside the current task's stack and strictly
    // below the live SP, and `erase_no_call` pushes nothing.
    unsafe { erase_no_call(start, len) };
    if irqs {
        // SAFETY: restoring the state observed above.
        unsafe { narf_arch::enable_interrupts() };
    }
}

pub fn exit(scope: DomainScope) {
    narf_arch::exit_domain_scope(scope.prev_domain);
    #[cfg(target_arch = "x86_64")]
    {
        if narf_arch::x86_64::pks::is_active() || narf_arch::x86_64::pcid::is_active() {
            // SAFETY: `scope.saved` came from the matching `enter_domain`, and
            // exit dispatches to the same backend that produced it. Unbalanced
            // here would leave PKRS narrowed or CR3 on a domain clone, and the
            // fault would land arbitrarily far away.
            unsafe {
                <narf_arch::x86_64::Pks as narf_arch::DomainPrimitive>::exit_domain(scope.saved)
            };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(saved) = scope.saved {
            // SAFETY: `saved` came from the matching `enter_domain`. Must run
            // even when the module's entry point returned an error: leaving
            // TCF at Sync would make every later untagged access to any tagged
            // page fault, arbitrarily far from here.
            unsafe { <narf_arch::aarch64::Mte as narf_arch::DomainPrimitive>::exit_domain(saved) };
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = scope;
    }
    // After the enforcer is restored, not before: erasing is ordinary kernel
    // work and should run under the kernel's own rights, not the module's.
    scrub_dead_stack();
}
