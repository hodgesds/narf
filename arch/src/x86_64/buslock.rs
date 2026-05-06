//! Intel Bus Lock Trap — IA32_DEBUGCTL.BUS_LOCK_DETECT.
//!
//! Spec: `arch/specification/cpu-atomics-mitigations.md` §2.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_DEBUGCTL: u32 = 0x1D9;
pub const DEBUGCTL_BUS_LOCK_DETECT: u64 = 1 << 2;

/// `true` iff CPUID(7, 0).ECX[24] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 valid.
    let (_, _, ecx, _) = unsafe { cpuid(7, 0) };
    ecx & (1 << 24) != 0
}

/// # Safety
/// CPL = 0; bus-lock-trap supported.
pub unsafe fn enable() {
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_IA32_DEBUGCTL) } | DEBUGCTL_BUS_LOCK_DETECT;
    unsafe {
        wrmsr(MSR_IA32_DEBUGCTL, v);
    }
}

/// # Safety
/// CPL = 0.
pub unsafe fn disable() {
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_IA32_DEBUGCTL) } & !DEBUGCTL_BUS_LOCK_DETECT;
    unsafe {
        wrmsr(MSR_IA32_DEBUGCTL, v);
    }
}
