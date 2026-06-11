//! FRED — Flexible Return and Event Delivery.
//!
//! Spec: `arch/specification/cpu-telemetry-qos.md` §2.
//!
//! v0.1 surfaces detection + the kernel-side configure path.
//! Wiring FRED handlers into the boot trampoline is a follow-up
//! that lives in `frame/`.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::cr::{read_cr4, write_cr4};
use crate::x86_64::msr::wrmsr;

pub const MSR_IA32_FRED_RSP1: u32 = 0x1CC;
pub const MSR_IA32_FRED_RSP2: u32 = 0x1CD;
pub const MSR_IA32_FRED_RSP3: u32 = 0x1CE;
pub const MSR_IA32_FRED_STKLVLS: u32 = 0x1CF;
pub const MSR_IA32_FRED_RSP0: u32 = 0x1D0;
pub const MSR_IA32_FRED_SSP1: u32 = 0x1D1;
pub const MSR_IA32_FRED_SSP2: u32 = 0x1D2;
pub const MSR_IA32_FRED_SSP3: u32 = 0x1D3;
pub const MSR_IA32_FRED_CONFIG: u32 = 0x1D4;

/// CR4.FRED — bit 32. (CR4 is 64-bit on x86_64.)
pub const CR4_FRED: u64 = 1 << 32;

/// `true` iff CPUID(7, 1).EAX[17] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return false;
    }
    // SAFETY: leaf 7 sub-leaf 1 valid.
    let (eax, _, _, _) = unsafe { cpuid(7, 1) };
    eax & (1 << 17) != 0
}

/// Set CR4.FRED. Legacy IDT delivery is replaced once this
/// is on; the boot trampoline must have programmed every FRED
/// MSR first.
///
/// # Safety
/// CPL = 0; FRED supported; FRED MSRs configured.
pub unsafe fn enable_cr4() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_cr4() };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    unsafe {
        write_cr4(v | CR4_FRED);
    }
}

/// Clear CR4.FRED — fall back to IDT delivery.
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable_cr4() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_cr4() };
    // SAFETY: the operation upholds its documented invariant (see surrounding context).
    unsafe {
        write_cr4(v & !CR4_FRED);
    }
}

/// Write the event-handler base into `IA32_FRED_CONFIG`. `va`
/// must be page-aligned (low 12 bits go to the NMI-bias and
/// reserved fields and must be 0 for v0.1 callers).
///
/// # Safety
/// CPL = 0; FRED supported.
pub unsafe fn write_handler_base(va: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_IA32_FRED_CONFIG, va);
    }
}

/// Set `IA32_FRED_RSP0` — the kernel stack used on event entry
/// from CPL = 3.
///
/// # Safety
/// CPL = 0; FRED supported.
pub unsafe fn write_rsp0(rsp: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_IA32_FRED_RSP0, rsp);
    }
}

/// Set the per-vector stack-level lookup (`IA32_FRED_STKLVLS`).
///
/// # Safety
/// CPL = 0; FRED supported.
pub unsafe fn write_stklvls(map: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_IA32_FRED_STKLVLS, map);
    }
}
