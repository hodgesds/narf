//! SMEP — Supervisor Mode Execution Prevention.
//!
//! CR4 bit 20. When set, an instruction fetch from a user-accessible
//! page (PTE.U=1) while CPL = 0 raises `#PF`. This kills the entire
//! class of "trick the kernel into jumping to attacker-controlled
//! userspace code" exploits — including the classic SMEP-pre-2011
//! `ret2usr` ROP chains. Detection cost: a CPUID(7, 0).EBX[7] check
//! once at boot. Runtime cost: zero — every instruction fetch already
//! consults the U/S bit; SMEP just promotes the result to a fault
//! instead of allowing the fetch.
//!
//! NARF stance: SMEP is mandatory at CPL=0 on every supported x86_64
//! part shipped after Ivy Bridge (2012); AMD added it with Bulldozer
//! Piledriver (2012). Both Renoir (Zen2) and Phoenix HawkPoint (Zen4)
//! support it unconditionally. If CPUID reports SMEP missing, NARF
//! refuses to set the bit — the architectural cost is "nothing
//! changes." There is no shut-off knob and no opt-out — this is the
//! "more secure than Linux" floor (Linux still ships `nosmep` for
//! debugging; NARF does not).
//!
//! References:
//!   * Intel SDM Vol 3 §4.6 — "Access Rights" (SMEP enforcement).
//!   * Linux `arch/x86/include/asm/cpufeatures.h` X86_FEATURE_SMEP.
//!   * Linus's smep enable in `arch/x86/kernel/cpu/common.c`
//!     (`setup_smep`).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::cr::{read_cr4, write_cr4};

/// CR4 bit 20. Architectural — Intel SDM Vol 3 §2.5.
pub const CR4_SMEP: u64 = 1 << 20;

/// `true` iff CPUID(7, 0).EBX[7] is set.
///
/// Both Zen2 Renoir and Zen4 Phoenix advertise this bit; an absent
/// bit means we're on a pre-2012 part or a VMM that hides it.
#[inline]
pub fn supported() -> bool {
    // SAFETY: CPUID is always legal at CPL=0.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 sub 0 is valid because max >= 7.
    let (_, ebx, _, _) = unsafe { cpuid(7, 0) };
    ebx & (1 << 7) != 0
}

/// Set CR4.SMEP. No-op if already set.
///
/// Must be called once per CPU after CR0.PG=1 (paging up) and before
/// the first user-mode entry. Order in the BSP boot is: GDT/IDT →
/// paging → SMEP → SMAP → SYSCALL setup → user-mode trampoline.
///
/// # Safety
/// CPL = 0; `supported()` returned true.
#[inline]
pub unsafe fn enable() {
    // SAFETY: caller-asserted. SMEP requires no other state and never
    // faults the writer (it only affects instruction fetches, which
    // can't be the very next instruction after the CR4 write).
    // SAFETY: Valid memory or trusted environment
    let v = unsafe { read_cr4() };
    if v & CR4_SMEP == 0 {
        // SAFETY: bit 20 is documented architectural; reserved bits
        // are preserved by the read-modify-write.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            write_cr4(v | CR4_SMEP);
        }
    }
}

/// Read-back: `true` iff CR4.SMEP is currently set on this CPU.
///
/// Used by AP bring-up to assert the BSP-mirrored CR4 took effect, and
/// by the security-init initcall to verify the boot path.
#[inline]
pub fn is_enabled() -> bool {
    // SAFETY: MOV from CR4 at CPL=0 is always defined.
    let v = unsafe { read_cr4() };
    v & CR4_SMEP != 0
}

/// Clear CR4.SMEP. Reserved for unit-test reset paths only.
///
/// **DO NOT call this from production code.** Disabling SMEP at
/// runtime would re-expose the entire ret2usr class of vulnerabilities
/// the security floor exists to prevent.
///
/// # Safety
/// CPL = 0.
#[inline]
pub unsafe fn disable_for_test() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_cr4() };
    // SAFETY: bit 20 clear is the architectural default.
    unsafe {
        write_cr4(v & !CR4_SMEP);
    }
}
