//! SMAP — Supervisor Mode Access Prevention.
//!
//! CR4 bit 21. When set, any data access (load or store) from a
//! supervisor-mode (CPL=0) instruction to a user-accessible page
//! (PTE.U=1) faults — *unless* the EFLAGS.AC bit is set. The
//! `STAC`/`CLAC` instructions set/clear AC atomically; everything in
//! between is an explicit "I am the kernel deliberately reaching
//! into user memory" annotation. Out of that window, the kernel
//! literally cannot touch user pages, full stop.
//!
//! NARF stance:
//!
//!   * Linux exposes `copy_from_user` / `copy_to_user` which open
//!     a per-call STAC/CLAC window and rely on developers calling
//!     the right helper. Forgetting it is a silent vulnerability
//!     class — a kernel that touches user memory directly will
//!     *succeed* on a non-SMAP CPU and *fault* on SMAP, so the bug
//!     stays latent on bring-up.
//!   * NARF wraps every user-memory touch in [`with_user_access`],
//!     which takes a closure. The compiler enforces lexical scope.
//!     Forgetting it is a *type* error (the user pointer surface
//!     is `unsafe` + needs the cap to even get the pointer), not
//!     a runtime check.
//!   * On Renoir + Phoenix the bit is always available; the
//!     `supported()` check is for QEMU TCG without `-cpu max`
//!     and for the same reason `cargo xtask test` includes a
//!     `Skip` path.
//!
//! References:
//!   * Intel SDM Vol 3 §4.6.1 — "User and Supervisor Mode Access".
//!   * AMD APM Vol 2 §5.5 — same.
//!   * Linux `arch/x86/include/asm/uaccess.h` (`user_access_begin` /
//!     `user_access_end`).
//!   * grsecurity UDEREF for the historical motivation (Brad
//!     Spengler's 2011 patch series; SMAP is the HW realisation).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::cr::{read_cr4, write_cr4};

/// Per-CPU marker for the interval where [`copy_user_guarded`] owns the
/// recoverable-probe slot (and, on SMAP hardware, has EFLAGS.AC set). A page
/// fault in this interval may heal synchronously, but it must never park for
/// reclaim: switching tasks would leave both pieces of CPU-local state live.
#[repr(C, align(64))]
struct GuardedCopyMarker {
    armed: AtomicBool,
    _pad: [u8; 63],
}

impl GuardedCopyMarker {
    const fn new() -> Self {
        Self {
            armed: AtomicBool::new(false),
            _pad: [0; 63],
        }
    }
}

const _: () = assert!(core::mem::size_of::<GuardedCopyMarker>() == 64);

static GUARDED_COPY: [GuardedCopyMarker; narf_lib::percpu::MAX_CPUS] =
    [const { GuardedCopyMarker::new() }; narf_lib::percpu::MAX_CPUS];

#[inline]
fn guarded_copy_marker_for(cpu: usize) -> &'static GuardedCopyMarker {
    &GUARDED_COPY[cpu.min(narf_lib::percpu::MAX_CPUS - 1)]
}

#[inline]
fn guarded_copy_marker() -> &'static GuardedCopyMarker {
    guarded_copy_marker_for(crate::current_cpu_id().raw() as usize)
}

/// Whether this CPU is inside [`copy_user_guarded`]'s probe/SMAP window.
///
/// The page-fault handler uses this to select the allocation-only demand-page
/// path. Reclaim parking is forbidden until the copy disarms the per-CPU probe
/// and closes its user-access window.
#[doc(hidden)]
#[inline]
pub fn guarded_copy_armed() -> bool {
    guarded_copy_marker().armed.load(Ordering::Acquire)
}

#[inline]
fn set_guarded_copy_armed_for(cpu: usize, armed: bool) {
    let marker = guarded_copy_marker_for(cpu);
    let old = marker.armed.load(Ordering::Relaxed);
    debug_assert_ne!(old, armed, "nested or unbalanced guarded user copy");
    // This record has one writer: its own CPU with IRQs masked. A release
    // store is sufficient for the synchronous fault handler's acquire load
    // and avoids a locked RMW on every copy chunk.
    marker.armed.store(armed, Ordering::Release);
}

/// CR4 bit 21. Architectural — Intel SDM Vol 3 §2.5.
pub const CR4_SMAP: u64 = 1 << 21;

/// `true` iff CPUID(7, 0).EBX[20] is set.
///
/// Renoir (Zen2) and Phoenix (Zen4) both set this bit. Older AMD
/// parts (Bulldozer, Piledriver, Steamroller) lack SMAP; the
/// `with_user_access` helper degrades to a plain closure call there
/// (still type-safe, just no HW enforcement).
#[inline]
pub fn supported() -> bool {
    // SAFETY: CPUID always legal at CPL=0.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 sub 0 valid because max >= 7.
    let (_, ebx, _, _) = unsafe { cpuid(7, 0) };
    ebx & (1 << 20) != 0
}

/// Set CR4.SMAP. No-op if already set.
///
/// # Safety
/// CPL = 0; `supported()` returned true.
#[inline]
pub unsafe fn enable() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_cr4() };
    if v & CR4_SMAP == 0 {
        // SAFETY: bit 21 reserved/preserved for non-SMAP CPUs is
        // unchanged by `read | CR4_SMAP` on a CPU that has the bit
        // (the caller proved `supported()`).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            write_cr4(v | CR4_SMAP);
        }
    }
}

/// Read-back: `true` iff CR4.SMAP is currently set on this CPU.
#[inline]
pub fn is_enabled() -> bool {
    // SAFETY: MOV from CR4 at CPL=0 always defined.
    let v = unsafe { read_cr4() };
    v & CR4_SMAP != 0
}

/// Set EFLAGS.AC (open the user-access window).
///
/// On a CPU without SMAP the instruction is a NOP (the bit exists
/// but enforces nothing). `STAC` is a single byte (`0F 01 CB`) and
/// is always safe to encode — it's been valid since Haswell.
///
/// # Safety
/// Should only be called via [`with_user_access`]; raw use risks
/// leaving the window open across a context switch (the kernel
/// would silently regain user-memory access for the next syscall).
#[inline(always)]
pub unsafe fn stac() {
    // SAFETY: encoding documented above; clobbers no registers.
    // NOT `nomem`/`preserves_flags`: STAC opens the EFLAGS.AC user-access
    // window, and the whole point is to gate the user-memory accesses that
    // follow. With `nomem` the optimizer treats this as side-effect-free and
    // is free to HOIST those accesses out of the STAC…CLAC window — sound in
    // a debug build (no reordering), a SMAP #PF in release. The bare asm acts
    // as a compiler memory barrier so the bracketed copy stays inside.
    unsafe {
        asm!("stac", options(nostack));
    }
}

/// Clear EFLAGS.AC (close the user-access window).
///
/// # Safety
/// Should only be called via [`with_user_access`].
#[inline(always)]
pub unsafe fn clac() {
    // SAFETY: encoding documented above; clobbers no registers.
    // See `stac`: NOT `nomem` — must act as a compiler barrier so the
    // bracketed user-memory copy can't be sunk past CLAC (window close).
    unsafe {
        asm!("clac", options(nostack));
    }
}

/// Bracket `f` with `STAC`/`CLAC` — the only sanctioned way to touch
/// user memory from kernel code.
///
/// This is the centrepiece of the "more secure than Linux" claim for
/// the kernel-to-user channel: missing brackets aren't a runtime bug,
/// they're a type-system error (every user-memory accessor in NARF's
/// surface takes a `&UserPtr<T>` whose deref is `unsafe` and is only
/// permitted inside this closure).
///
/// On CPUs without SMAP the STAC/CLAC are NOPs (no AC bit to toggle)
/// and the closure executes verbatim — the kernel still upholds the
/// type-level invariant, just without HW enforcement.
///
/// # Safety
/// `f` must not switch context, sleep across an await, or call into
/// any path that itself opens a nested user-access window. The closure
/// body is short-lived and only accesses user pointers it has
/// pre-validated (range + alignment + capability).
#[inline]
pub unsafe fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    // SAFETY: STAC is a NOP on non-SMAP CPUs and a single-instruction
    // EFLAGS.AC toggle on SMAP CPUs. Either way it doesn't touch
    // memory or other regs.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        stac();
    }
    let r = f();
    // SAFETY: same.
    unsafe {
        clac();
    }
    r
}

/// Fault-guarded kernel↔user byte copy — the transfer tail of NARF's
/// `copy_from_user` / `copy_to_user` (Linux analogue:
/// `arch/x86/lib/copy_user_64.S` plus its exception-table fixups).
///
/// Runs `rep movsb` inside a STAC/CLAC window with the per-CPU
/// recoverable probe (`crate::x86_64::probe`) armed. Faults the trap
/// handler can heal transparently — demand-paging a fresh mmap page,
/// stack growth, COW split — run FIRST on the #PF path and `iretq`
/// back to the faulting `rep movsb`, which resumes cleanly (its whole
/// state lives in RCX/RSI/RDI); the probe never fires for those. Only
/// faults with no recovery reach `probe::consume` and redirect to the
/// local label past the copy:
///
///   * `#GP` — non-canonical linear address, the only #GP a 64-bit
///     data access can raise. Reachable when a *validated* base is
///     canonical but a mid-copy address is not; `validate_user_range`
///     pre-rejects these now, this is defence-in-depth.
///   * `#PF` the demand pager refused — the address lies in no region
///     of the active AS, e.g. a sibling thread `munmap`ed the buffer
///     between syscall-entry validation and the copy (the TOCTOU
///     stress-ng --vma hits constantly). Linux returns -EFAULT via
///     the extable; so do we now, instead of a kernel panic.
///
/// Returns `Ok(())` on a complete copy, `Err(bytes_remaining)` when a
/// fault was caught (`bytes_remaining` counts the not-copied tail of
/// the whole `len`; always > 0 on `Err`).
///
/// The transfer is chunked (64 KiB) and each chunk runs with IRQs
/// disabled: the probe slot is per-CPU and single-depth, so an
/// IRQ-driven context switch while armed would let another task on
/// this CPU clobber the armed probe (the same latent constraint
/// `msr::rdmsr_or_gp` has, but a bulk copy is a much longer window
/// than one `rdmsr`). 64 KiB bounds each IRQ-off window to a few µs
/// on ERMSB parts; the 16 MiB `MAX_USER_COPY` worst case is 256 short
/// windows, not one 16 MiB blackout.
///
/// # Safety
/// - CPL = 0, not IRQ context.
/// - The *kernel* side (`dst` for a from-user copy, `src` for a
///   to-user copy) must be valid for `len` bytes. The *other* side
///   may be an arbitrary (even hostile) user pointer — surviving it
///   is the point of this helper.
#[cfg(target_arch = "x86_64")]
pub unsafe fn copy_user_guarded(dst: *mut u8, src: *const u8, len: usize) -> Result<(), usize> {
    use core::sync::atomic::{compiler_fence, Ordering};

    use crate::x86_64::probe;

    const CHUNK: usize = 64 * 1024;
    let mut done = 0usize;
    while done < len {
        let n = core::cmp::min(CHUNK, len - done);
        // Save IF, then CLI: no context switch may run while the
        // probe is armed (single per-CPU slot).
        let saved_rflags: u64;
        // SAFETY: pushfq/pop/cli are always legal at CPL=0. Not
        // `nostack` (pushfq uses the stack); not `preserves_flags`
        // (cli clears IF).
        unsafe {
            asm!("pushfq", "pop {f}", "cli", f = out(reg) saved_rflags);
        }
        // IRQ masking pins execution to this CPU until the probe and SMAP
        // window are both closed. Resolve the per-CPU slot once: the former
        // marker/probe helpers each executed RDTSCP independently (four reads
        // per 4 KiB pipe syscall) despite all four indices being identical.
        let cpu = crate::current_cpu_id().raw() as usize;
        let recovery: u64;
        // SAFETY: LEA of a local label. `98f` resolves forward into
        // the copy block below — GAS numeric labels span asm blocks
        // emitted in order; same pattern as `msr::rdmsr_or_gp`.
        unsafe {
            asm!(
                "lea {r}, [98f + rip]",
                r = out(reg) recovery,
                options(nostack, preserves_flags),
            );
        }
        set_guarded_copy_armed_for(cpu, true);
        probe::arm_for_cpu(cpu, recovery);
        // SAFETY: open the user-access window; the matching `clac`
        // below runs on both the fall-through and the recovery path
        // (label 98 sits before it).
        unsafe {
            stac();
        }
        let remaining: usize;
        compiler_fence(Ordering::SeqCst);
        // SAFETY: on an unrecoverable fault the trap handler rewrites
        // the frame RIP to label 98 with RCX = bytes not yet copied,
        // RSI/RDI at the fault point — `rep movsb` is restartable and
        // abandonable by design. On a healed #PF the iretq re-executes
        // `rep movsb` with the same registers and the copy continues.
        unsafe {
            asm!(
                "rep movsb",
                "98:",
                inout("rcx") n => remaining,
                inout("rsi") src.add(done) => _,
                inout("rdi") dst.add(done) => _,
                options(nostack),
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: close the user-access window before anything else.
        unsafe {
            clac();
        }
        let caught = probe::disarm_for_cpu(cpu);
        set_guarded_copy_armed_for(cpu, false);
        // Restore IF exactly as found.
        if saved_rflags & (1 << 9) != 0 {
            // SAFETY: re-enabling interrupts we disabled above.
            unsafe {
                asm!("sti", options(nostack));
            }
        }
        if caught.vector.is_some() {
            return Err(len - done - (n - remaining));
        }
        done += n;
    }
    Ok(())
}

/// Clear CR4.SMAP. Reserved for unit-test reset paths only.
///
/// **DO NOT call this from production code.**
///
/// # Safety
/// CPL = 0.
#[inline]
pub unsafe fn disable_for_test() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_cr4() };
    // SAFETY: clearing bit 21 is architecturally legal.
    unsafe {
        write_cr4(v & !CR4_SMAP);
    }
}

/// Read EFLAGS.AC. Useful for tests that want to verify the
/// STAC/CLAC bracket actually flipped the bit on SMAP-capable HW.
#[inline]
pub fn read_ac() -> bool {
    let f: u64;
    // SAFETY: PUSHFQ + POP is always legal at CPL=0.
    unsafe {
        asm!(
            "pushfq",
            "pop {f}",
            f = out(reg) f,
            options(nostack, preserves_flags),
        );
    }
    f & (1 << 18) != 0
}
