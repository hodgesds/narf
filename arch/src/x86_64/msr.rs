//! Model-specific register access. Every entry point carries the
//! `compiler_fence(SeqCst)` pair discipline from `arch/` §4.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// MSR index: `IA32_EFER`.
pub const IA32_EFER: u32 = 0xC000_0080;
/// `IA32_EFER.NXE` — NX-bit enable. When set, PTE bit 63 becomes the
/// "no-execute" bit; otherwise it's reserved-zero.
pub const IA32_EFER_NXE: u64 = 1 << 11;
/// MSR index: `IA32_PKRS` — protection-key rights for supervisor.
/// Accessible only when `CR4.PKS = 1`.
pub const IA32_PKRS: u32 = 0x0000_06E1;

/// Read a 64-bit MSR.
///
/// # Safety
/// - `RDMSR` at CPL=0 is legal; with an unsupported `index` some
///   CPUs raise `#GP` and others return zeros. Stage 1/2 probes
///   the relevant MSRs via CPUID before calling this, so no `#GP`
///   is expected on a probed path.
#[inline]
pub unsafe fn rdmsr(index: u32) -> u64 {
    let low: u32;
    let high: u32;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller verified the MSR exists via CPUID.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") index,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
    ((high as u64) << 32) | (low as u64)
}

/// Write a 64-bit MSR.
///
/// # Safety
/// - Same CPUID-presence precondition as `rdmsr`.
/// - Writing to security-sensitive MSRs (IA32_EFER, IA32_PKRS,
///   CR3, TCR_ELx) requires the compiler_fence pair so fat LTO
///   doesn't reorder loads/stores across the write (see arch/ §4).
#[inline]
pub unsafe fn wrmsr(index: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller verified the MSR exists and that writing `value`
    // is a defined operation for this MSR.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") index,
            in("eax") low,
            in("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
}

/// Why a fallible MSR access surfaced an error.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsrFault {
    /// `#GP` (vector 13) — the most common BIOS-locks-MSR outcome
    /// (e.g. AMD CPPC MSRs locked by firmware on some Zen2 OEMs).
    GeneralProtection,
    /// Any other CPU exception during the access (`#UD`, `#PF` on
    /// the inline-asm fetch, etc.). The vector lets the caller
    /// distinguish without re-running.
    OtherTrap(u32),
}

/// Read a 64-bit MSR, catching `#GP` instead of panicking.
///
/// Arms the per-CPU recoverable probe at a label past `rdmsr`, so a
/// `#GP` on an unsupported / firmware-locked MSR redirects to that
/// label and returns `Err(MsrFault::GeneralProtection)`. Use for
/// MSRs whose presence is *plausible but not guaranteed* — anything
/// guaranteed by CPUID should keep using plain `rdmsr`.
///
/// Single-probe-at-a-time model (Stage 2 BSP-only). Concurrent calls
/// on the same CPU race each other's probe state.
pub fn rdmsr_or_gp(index: u32) -> Result<u64, MsrFault> {
    use crate::x86_64::probe;
    let recovery: u64;
    // SAFETY: LEA of a local label is always defined.
    unsafe {
        asm!(
            "lea {rec}, [99f + rip]",
            rec = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);
    let low: u32;
    let high: u32;
    compiler_fence(Ordering::SeqCst);
    // SAFETY: probe-armed rdmsr; on #GP the trap handler redirects
    // RIP to label 99 below, where low/high stay uninit but get
    // overwritten by the `Err` arm.
    unsafe {
        asm!(
            "rdmsr",
            "99:",
            in("ecx") index,
            lateout("eax") low,
            lateout("edx") high,
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
    let caught = probe::disarm();
    match caught.vector {
        None => Ok(((high as u64) << 32) | (low as u64)),
        Some(13) => Err(MsrFault::GeneralProtection),
        Some(v) => Err(MsrFault::OtherTrap(v)),
    }
}

/// Write a 64-bit MSR, catching `#GP` instead of panicking.
///
/// Same probe-armed pattern as [`rdmsr_or_gp`]. Use for MSRs that
/// may be BIOS-locked (AMD CPPC enable / req on some Zen2 OEMs) or
/// expect a pre-enable handshake we may not have performed yet.
///
/// Single-probe-at-a-time model — see `rdmsr_or_gp`.
pub fn wrmsr_or_gp(index: u32, value: u64) -> Result<(), MsrFault> {
    use crate::x86_64::probe;
    let low = value as u32;
    let high = (value >> 32) as u32;
    let recovery: u64;
    // SAFETY: LEA of a local label is always defined.
    unsafe {
        asm!(
            "lea {rec}, [99f + rip]",
            rec = out(reg) recovery,
            options(nostack, preserves_flags),
        );
    }
    probe::arm(recovery);
    compiler_fence(Ordering::SeqCst);
    // SAFETY: probe-armed wrmsr; #GP recovers at label 99.
    unsafe {
        asm!(
            "wrmsr",
            "99:",
            in("ecx") index,
            in("eax") low,
            in("edx") high,
            options(nostack, preserves_flags),
        );
    }
    compiler_fence(Ordering::SeqCst);
    let caught = probe::disarm();
    match caught.vector {
        None => Ok(()),
        Some(13) => Err(MsrFault::GeneralProtection),
        Some(v) => Err(MsrFault::OtherTrap(v)),
    }
}
