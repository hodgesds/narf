//! Model-specific register access. Every entry point carries the
//! `compiler_fence(SeqCst)` pair discipline from `arch/` §4.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, Ordering};

/// MSR index: `IA32_EFER`.
pub const IA32_EFER: u32 = 0xC000_0080;
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
    let low  = value as u32;
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
