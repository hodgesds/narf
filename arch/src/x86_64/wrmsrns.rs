//! WRMSRNS — non-serialising MSR write.
//!
//! Spec: `arch/specification/cpu-perf-niche.md` §4.
//!
//! Encoded `0F 01 C6`. Functionally identical to `WRMSR`
//! (`ECX = msr`, `EDX:EAX = value`) minus the architectural
//! serialising side-effect — the next instruction is allowed
//! to issue out of order. Sapphire Rapids+.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::wrmsr;

/// `true` iff CPUID(7, 1).EAX[19] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 sub-leaf 1 valid.
    let (eax, _, _, _) = unsafe { cpuid(7, 1) };
    eax & (1 << 19) != 0
}

/// Non-serialising MSR write.
///
/// # Safety
/// CPL = 0; WRMSRNS supported (`#UD` otherwise); `value`
/// matches the architectural format for `msr`.
#[inline]
pub unsafe fn wrmsrns(msr: u32, value: u64) {
    let lo = value as u32;
    let hi = (value >> 32) as u32;
    // SAFETY: caller-asserted.
    unsafe {
        core::arch::asm!(
            ".byte 0x0F, 0x01, 0xC6",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags),
        );
    }
}

/// Convenience: WRMSRNS when supported, WRMSR otherwise.
///
/// # Safety
/// CPL = 0.
#[inline]
pub unsafe fn write(msr: u32, value: u64) {
    if supported() {
        // SAFETY: gated.
        unsafe {
            wrmsrns(msr, value);
        }
    } else {
        // SAFETY: caller-asserted.
        unsafe {
            wrmsr(msr, value);
        }
    }
}
