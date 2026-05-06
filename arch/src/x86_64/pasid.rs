//! x86_64 PASID — Process-Address-Space-ID for accelerator SVA.
//!
//! Spec: `arch/specification/cpu-compute-confidential.md` §5.
//!
//! `IA32_PASID` (`0xD93`) tags every memory request from this
//! logical processor with a 20-bit PASID + valid bit. IOMMUs
//! configured for Shared Virtual Memory (SVA) translate the
//! tagged accesses against the matching process page table.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_PASID: u32 = 0xD93;

const PASID_VALID: u64 = 1 << 31;

/// `true` iff CPUID(7, 0).ECX[2] is set (the conventional
/// indicator that the IA32_PASID MSR is implemented). Treat as
/// best-effort; callers that need stronger evidence should
/// probe the MSR via the standard read-after-write idiom.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 valid.
    let (_, _, ecx, _) = unsafe { cpuid(7, 0) };
    ecx & (1 << 2) != 0
}

/// Read `IA32_PASID`.
///
/// # Safety
/// CPL = 0; PASID supported.
pub unsafe fn read() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_PASID) }
}

/// Write a PASID + valid bit.
///
/// # Safety
/// CPL = 0; PASID supported; `pasid` fits in 20 bits.
pub unsafe fn write(pasid: u32) {
    let v = (pasid as u64 & 0xFFFFF) | PASID_VALID;
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_IA32_PASID, v);
    }
}

/// Clear the valid bit.
///
/// # Safety
/// CPL = 0; PASID supported.
pub unsafe fn invalidate() {
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_IA32_PASID, 0);
    }
}
