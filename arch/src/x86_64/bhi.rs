//! x86_64 BHI controls — `IA32_SPEC_CTRL.BHI_DIS_S`.
//!
//! Spec: `arch/specification/cpu-compute-confidential.md` §4.
//!
//! BHI (Branch History Injection, Spectre-BHB on AMD) is
//! mitigated either by silicon (`BHI_NO`) or by setting the
//! BHI_DIS_S bit in IA32_SPEC_CTRL on supervisor entry.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};
use crate::x86_64::spec_ctrl::MSR_IA32_SPEC_CTRL;

/// `IA32_SPEC_CTRL.BHI_DIS_S` — bit 10.
pub const SPEC_CTRL_BHI_DIS_S: u64 = 1 << 10;

/// `true` iff the CPU advertises CPUID(7, 2).EDX[4] = `BHI_NO`
/// (silicon already immune; no mitigation needed).
pub fn bhi_no() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return false; }
    // SAFETY: leaf 7 sub-leaf 2 valid.
    let (_, _, _, edx) = unsafe { cpuid(7, 2) };
    edx & (1 << 4) != 0
}

/// `true` iff `IA32_SPEC_CTRL` exists and the BHI_DIS_S bit is
/// architecturally defined. Conservative — we treat presence of
/// SPEC_CTRL + absence of `BHI_NO` as evidence the bit may be
/// honoured. Callers are free to verify by writing + reading
/// back.
pub fn bhi_dis_s_supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return false; }
    // SAFETY: leaf 7 sub-leaf 0 valid.
    let (_, _, _, edx) = unsafe { cpuid(7, 0) };
    let spec_ctrl_msr = edx & (1 << 26) != 0; // IBRS / IBPB available implies SPEC_CTRL
    spec_ctrl_msr && !bhi_no()
}

/// Set `IA32_SPEC_CTRL.BHI_DIS_S`.
///
/// # Safety
/// CPL = 0; `bhi_dis_s_supported()` (read-modify-write of
/// `IA32_SPEC_CTRL` is otherwise a no-op or a `#GP` depending
/// on platform).
pub unsafe fn enable_bhi_dis_s() {
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_IA32_SPEC_CTRL) };
    unsafe { wrmsr(MSR_IA32_SPEC_CTRL, v | SPEC_CTRL_BHI_DIS_S); }
}

/// Clear the bit.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable_bhi_dis_s() {
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_IA32_SPEC_CTRL) };
    unsafe { wrmsr(MSR_IA32_SPEC_CTRL, v & !SPEC_CTRL_BHI_DIS_S); }
}
