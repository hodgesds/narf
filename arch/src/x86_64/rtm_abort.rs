//! Intel RTM_ALWAYS_ABORT — TSX kill-switch.
//!
//! Spec: `arch/specification/cpu-mem-encrypt-virt.md` §2.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_TSX_FORCE_ABORT: u32 = 0x10F;

pub const TSX_FORCE_ABORT_RTM:           u64 = 1 << 0;
pub const TSX_FORCE_ABORT_TSX_CPUID_CLEAR: u64 = 1 << 1;
pub const TSX_FORCE_ABORT_SDV_ENABLE_RTM:  u64 = 1 << 2;

/// `true` iff CPUID(7, 0).EDX[11] is set.
pub fn rtm_always_abort_supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return false; }
    // SAFETY: leaf 7 valid.
    let (_, _, _, edx) = unsafe { cpuid(7, 0) };
    edx & (1 << 11) != 0
}

/// # Safety
/// CPL = 0; RTM_ALWAYS_ABORT supported.
pub unsafe fn read_force_abort() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_TSX_FORCE_ABORT) }
}

pub unsafe fn write_force_abort(v: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_TSX_FORCE_ABORT, v); }
}

/// Force every `XBEGIN` to abort; safe baseline for boot.
///
/// # Safety
/// CPL = 0; RTM_ALWAYS_ABORT supported.
pub unsafe fn force_rtm_abort() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_force_abort() } | TSX_FORCE_ABORT_RTM;
    unsafe { write_force_abort(v); }
}
