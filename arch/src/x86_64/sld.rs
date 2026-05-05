//! Intel Split Lock Detect — IA32_TEST_CTRL.
//!
//! Spec: `arch/specification/cpu-atomics-mitigations.md` §1.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_CORE_CAPABILITIES: u32 = 0xCF;
pub const MSR_IA32_TEST_CTRL:         u32 = 0x33;

pub const TEST_CTRL_SLD_DISABLE_AC_GP: u64 = 1 << 29;
pub const TEST_CTRL_SLD_AC_VOTE:       u64 = 1 << 30;
pub const TEST_CTRL_SLD_DISABLE_AC:    u64 = 1 << 31;

const CORE_CAPS_SLD: u64 = 1 << 5;

/// `true` iff CPUID(7, 0).EDX[5] is set (CORE_CAPABILITIES MSR
/// present) **and** `IA32_CORE_CAPABILITIES.SPLIT_LOCK_DETECT`
/// is reported. CORE_CAPABILITIES read needs CPL = 0; we avoid
/// it here and let `unsafe { supported_unsafe() }` do the MSR
/// probe in privileged paths.
pub fn cpuid_gate() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return false; }
    // SAFETY: leaf 7 valid.
    let (_, _, _, edx) = unsafe { cpuid(7, 0) };
    edx & (1 << 5) != 0
}

/// # Safety
/// CPL = 0; CORE_CAPABILITIES advertised per `cpuid_gate()`.
pub unsafe fn supported_unsafe() -> bool {
    if !cpuid_gate() { return false; }
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_IA32_CORE_CAPABILITIES) };
    v & CORE_CAPS_SLD != 0
}

/// # Safety
/// CPL = 0; SLD supported.
pub unsafe fn read_test_ctrl() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_TEST_CTRL) }
}

pub unsafe fn write_test_ctrl(v: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_TEST_CTRL, v); }
}

/// Enable split-lock detection in `#AC` mode (raise alignment-
/// check exceptions on split locks rather than silently
/// translating them).
///
/// # Safety
/// CPL = 0; SLD supported.
pub unsafe fn enable_ac() {
    // SAFETY: caller-asserted.
    let mut v = unsafe { read_test_ctrl() };
    v &= !TEST_CTRL_SLD_DISABLE_AC;
    v |=  TEST_CTRL_SLD_DISABLE_AC_GP;
    unsafe { write_test_ctrl(v); }
}

/// Disable detection.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_test_ctrl() } | TEST_CTRL_SLD_DISABLE_AC;
    unsafe { write_test_ctrl(v); }
}
