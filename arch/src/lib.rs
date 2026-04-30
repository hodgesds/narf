//! narf-arch — hardware abstraction layer.
//!
//! Spec: `arch/specification/spec.md`. Stage 1 lands the primitives needed
//! to reach a serial `write_str` from a bare boot: `halt`, `disable_interrupts`,
//! and I/O-port / MMIO access wrappers. Each wrapper carries the
//! `compiler_fence(SeqCst)` discipline from §4 to defeat fat-LTO reorders.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

pub mod mmio;
pub mod percpu;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64 as current;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64 as current;

/// Backend that is *currently enforcing* driver-domain isolation.
///
/// `Pks` and `Mte` are hardware-fast, single-instruction switches. `Pcid`
/// is the AMD-x86_64 / pre-SPR-Intel fallback: per-domain page tables
/// tagged with PCIDs, switched by `MOV CR3` (correct, but ~50–100 cycles
/// per crossing instead of the WRMSR-class cost of PKS). `Sfi` is
/// reserved for a future software-fault-isolation backend; not currently
/// implemented.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DomainBackend { Pks, Mte, Pcid, Sfi }

/// The *static-shape* primitive picked at compile time from the target
/// arch. On x86_64 this is `Pks`, on aarch64 it is `Mte`. Code that
/// names `narf_arch::Domain::save()` etc. is calling through this type.
///
/// On AMD silicon (no PKS), the **active** enforcer is `Pcid`, but the
/// type alias still resolves to `Pks` — `Pks::save/restore/...` are
/// architecturally legal no-ops on AMD because CR4.PKS will not be set
/// and the boot path skips the PKRS-mutating helpers. The single
/// authoritative answer for "what is currently enforcing isolation?"
/// is `effective_backend()`, not the const below.
///
/// This split exists because `arch/` is `no_std` and trait selection
/// has to happen at the type level, but the framekernel needs to log
/// the *runtime* enforcer ("pks" vs "pcid fallback") without taking a
/// dep on `frame/`. The cell below is the runtime answer.
#[cfg(target_arch = "x86_64")]
pub const BACKEND: DomainBackend = DomainBackend::Pks;
#[cfg(target_arch = "aarch64")]
pub const BACKEND: DomainBackend = DomainBackend::Mte;

/// Runtime-selected backend cell. Boot-time code in `frame/` calls
/// `set_effective_backend(Pcid)` after CPUID detection on AMD silicon.
/// Until that call lands, `effective_backend()` returns the compile-time
/// `BACKEND` so existing call sites observe today's behaviour.
///
/// This is a relaxed-ordered `AtomicU8` because backend selection
/// happens once during BSP boot before any AP is up; later reads only
/// need to observe the post-init value, not synchronise with anything.
mod effective {
    use core::sync::atomic::{AtomicU8, Ordering};
    use super::DomainBackend;

    // 0xFF sentinel = "not yet set; fall back to compile-time BACKEND".
    static CELL: AtomicU8 = AtomicU8::new(0xFF);

    const fn encode(b: DomainBackend) -> u8 {
        match b {
            DomainBackend::Pks  => 0,
            DomainBackend::Mte  => 1,
            DomainBackend::Pcid => 2,
            DomainBackend::Sfi  => 3,
        }
    }
    fn decode(v: u8) -> Option<DomainBackend> {
        Some(match v {
            0 => DomainBackend::Pks,
            1 => DomainBackend::Mte,
            2 => DomainBackend::Pcid,
            3 => DomainBackend::Sfi,
            _ => return None,
        })
    }

    pub fn set(b: DomainBackend) { CELL.store(encode(b), Ordering::Relaxed) }
    pub fn get() -> Option<DomainBackend> { decode(CELL.load(Ordering::Relaxed)) }
}

/// Set the runtime-effective domain enforcer. Called once during BSP
/// boot from `frame/main.rs` after CPUID + arch feature probing.
pub fn set_effective_backend(b: DomainBackend) { effective::set(b) }

/// Read the runtime-effective domain enforcer. If `set_effective_backend`
/// has not yet been called (very-early boot), falls back to the
/// compile-time `BACKEND` so call sites do not observe a sentinel.
pub fn effective_backend() -> DomainBackend {
    effective::get().unwrap_or(BACKEND)
}

/// Per-arch domain-rights primitive.
///
/// x86_64 backs this with PKS (`IA32_PKRS` + PTE PK field). aarch64
/// backs it with MTE (`SCTLR_EL1.TCF` + pointer tag bits). The two
/// differ structurally — PKS does rights with a single MSR write;
/// MTE encodes rights in pointer tags per 16-byte granule — but both
/// expose the same coarse save / restore / rights-mutation surface.
///
/// Stage-2 status:
///   * x86_64 impl: fully live (`arch::x86_64::Pks`).
///   * aarch64 impl: stub (`arch::aarch64::Mte`) — methods
///     `unimplemented!`; the trait shape is carved out so consumers
///     can depend on it today and the real impl lands without API
///     churn when MTE work begins.
pub trait DomainPrimitive {
    const BACKEND: DomainBackend;
    type SavedState: Copy;
    type Rights: Copy + Eq;

    /// All-allow rights. Default initial PKRS / "TCF off" for aarch64.
    const ALLOW_ALL: Self::Rights;
    /// Read-only: writes fault, reads allowed.
    const READ_ONLY: Self::Rights;
    /// All-deny: any access faults.
    const DENY_ALL:  Self::Rights;

    /// Snapshot the current domain-rights state.
    ///
    /// # Safety
    /// Backend preconditions (e.g. CR4.PKS=1 for the PKS impl) must hold.
    unsafe fn save() -> Self::SavedState;

    /// Restore a previously-saved domain-rights state.
    ///
    /// # Safety
    /// Same as `save`.
    unsafe fn restore(s: Self::SavedState);

    /// Read the rights for a single domain.
    ///
    /// # Safety
    /// Same as `save`. `domain` must be in 0..=15.
    unsafe fn get_rights(domain: u8) -> Self::Rights;

    /// Write rights for one domain without disturbing the other 15.
    ///
    /// # Safety
    /// Same as `save`. `domain` must be in 0..=15.
    unsafe fn set_rights(domain: u8, rights: Self::Rights);

    /// Enter a domain scope — rights allow only the two named
    /// domains. Returns the previous saved state for `exit_domain`.
    /// Backends typically implement this as a single atomic mutation
    /// (PKS: one `WRMSR IA32_PKRS`).
    ///
    /// # Safety
    /// Same as `save`. Both domain numbers must be in 0..=15.
    unsafe fn enter_domain(
        kernel_domain: u8,
        driver_domain: u8,
    ) -> Self::SavedState;

    /// Symmetric exit from a scope started by `enter_domain`.
    ///
    /// # Safety
    /// Same as `restore`.
    unsafe fn exit_domain(saved: Self::SavedState);
}

/// The active architecture's `DomainPrimitive` implementation. Type
/// alias so consumers write `arch::Domain::save()` regardless of arch.
#[cfg(target_arch = "x86_64")]
pub type Domain = current::Pks;
#[cfg(target_arch = "aarch64")]
pub type Domain = current::Mte;

/// Spin-halt the current CPU forever. Used on panic and end-of-boot.
#[inline(always)]
pub fn halt_forever() -> ! { current::halt_forever() }

/// 128-bit atomic compare-and-swap.
///
/// # Safety
/// `ptr` must be 16-byte aligned.
#[inline(always)]
pub unsafe fn cas128(ptr: *mut u128, old: u128, new: u128) -> Result<u128, u128> {
    unsafe { current::cas128(ptr, old, new) }
}

/// Atomically replace a 4-byte instruction word. Used by `tracing/` for
/// runtime probe arming. Per-arch `asm.rs` implements the required
/// self-modifying-code synchronisation.
///
/// # Safety
/// `addr` must be 4-byte aligned and refer to memory that is both
/// writable and executable (typically a kernel-writable alias of the
/// probe site). On SMP NARF the caller must also arrange for every
/// other CPU to serialise before it next fetches the patched word —
/// Stage 3 is single-CPU, so the local flush is enough.
#[inline(always)]
pub unsafe fn patch_word(addr: *mut u32, new: u32) {
    // SAFETY: delegated to the per-arch helper; contract above.
    unsafe { current::patch_word(addr, new); }
}

/// ID of the CPU currently executing this code. Stage-2 single-CPU
/// returns `0`; Stage-3 AP bring-up replaces the body with a real
/// read (TPIDR_EL1 on aarch64, MSR GS-based on x86_64).
#[inline]
pub fn current_cpu_id() -> narf_lib::id::CpuId {
    narf_lib::id::CpuId::new(narf_arch_cpu_id() as u16)
}

/// Hook that `narf_lib::percpu` calls to avoid a dep cycle.
/// Reads the current logical CPU id via the per-arch `cpu`
/// module (RDTSCP/IA32_TSC_AUX on x86_64; MPIDR_EL1 lookup on
/// aarch64). Single-CPU today: returns 0 because the BSP's
/// per-CPU storage hasn't been populated with a non-zero id;
/// AP bring-up will start writing real ids.
#[unsafe(no_mangle)]
pub extern "Rust" fn narf_arch_cpu_id() -> usize {
    current::cpu::current_cpu() as usize
}

/// Hook that `narf_lib::assert::current_domain` calls to avoid a dep
/// cycle. Stage 3 returns 0 (`DomainId::FRAME`) — the Stage-2 bring-up
/// runs every task in-Frame. Stage 4 replaces the body with a live
/// PKRU / PKRS / TCF-derived read once per-task domain tracking lands.
/// Returning an out-of-range value here would cause `DomainId::new`
/// to panic at construction, so the body is intentionally conservative.
#[unsafe(no_mangle)]
pub extern "Rust" fn narf_arch_current_domain() -> u8 {
    0
}

/// Halt until the next interrupt. On x86_64 falls back to `spin_loop`
/// when IRQs are masked (HLT would otherwise deadlock). On aarch64 uses
/// WFI, which wakes on IRQ regardless of mask state.
#[inline(always)]
pub fn halt_until_irq() { current::asm::halt_until_irq() }

/// End the kernel run with an exit code. Under QEMU this triggers a clean
/// VM exit; on real hardware / other VMMs it falls back to `halt_forever`.
/// `code == 0` is "normal success"; non-zero is "failure" — verification
/// harnesses map these to `cargo xtask test` pass/fail.
///
/// # Safety
/// Per-arch backend may touch a platform-specific exit device; see
/// `arch::current::exit_qemu` for the x86_64 implementation and the
/// aarch64 semihosting path.
pub unsafe fn exit_kernel(code: u32) -> ! {
    // SAFETY: backend owns the platform contract.
    unsafe { current::exit_qemu(code) }
}

/// Disable interrupts on the current CPU. Stage 1 only — proper save/restore
/// typestate comes with `frame/`'s IRQ context token.
#[inline(always)]
pub unsafe fn disable_interrupts() {
    // SAFETY: arch backend upholds the compiler_fence discipline from §4.
    unsafe { current::disable_interrupts() }
}

/// Enable interrupts on the current CPU.
#[inline(always)]
pub unsafe fn enable_interrupts() {
    // SAFETY: caller must hold the equivalent capability (Stage 3); Stage 1
    // has a single domain so the check is vacuous.
    unsafe { current::enable_interrupts() }
}
