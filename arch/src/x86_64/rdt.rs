//! Intel RDT — CAT / CMT / MBM / MBA.
//!
//! Spec: `arch/specification/cpu-telemetry-qos.md` §1.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_QM_EVTSEL: u32 = 0xC8D;
pub const MSR_QM_CTR: u32 = 0xC8E;
pub const MSR_PQR_ASSOC: u32 = 0xC8F;
pub const MSR_L3_QOS_BASE: u32 = 0xC90;
pub const MSR_L2_QOS_BASE: u32 = 0xD10;
pub const MSR_MBA_BASE: u32 = 0xD50;

pub const EVT_L3_OCCUPANCY: u32 = 0x01;
pub const EVT_TOTAL_MEM_BW: u32 = 0x02;
pub const EVT_LOCAL_MEM_BW: u32 = 0x03;

#[derive(Copy, Clone, Debug, Default)]
pub struct RdtCaps {
    pub monitoring: bool,
    pub allocation: bool,
    pub l3_monitoring: bool,
    pub l3_cat: bool,
    pub l2_cat: bool,
    pub mba: bool,
    pub max_rmid: u32,
    pub max_closid: u32,
}

pub fn caps() -> RdtCaps {
    let mut c = RdtCaps::default();
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 {
        return c;
    }
    // SAFETY: leaf 7 valid.
    let (_, ebx, _, _) = unsafe { cpuid(7, 0) };
    c.monitoring = ebx & (1 << 12) != 0;
    c.allocation = ebx & (1 << 15) != 0;

    if c.monitoring && max >= 0x0F {
        // SAFETY: gated.
        let (_, ebx, _, edx) = unsafe { cpuid(0x0F, 0) };
        if edx & (1 << 1) != 0 {
            c.l3_monitoring = true;
            c.max_rmid = ebx;
        }
    }
    if c.allocation && max >= 0x10 {
        // SAFETY: gated.
        let (_, ebx, _, _) = unsafe { cpuid(0x10, 0) };
        c.l3_cat = ebx & (1 << 1) != 0;
        c.l2_cat = ebx & (1 << 2) != 0;
        c.mba = ebx & (1 << 3) != 0;
        if c.l3_cat {
            // SAFETY: gated.
            let (_, _, _, edx) = unsafe { cpuid(0x10, 1) };
            c.max_closid = edx & 0xFFFF;
        }
    }
    c
}

/// Bind the current CPU to `(rmid, closid)`.
///
/// # Safety
/// CPL = 0; RDT supported.
pub unsafe fn assoc(rmid: u16, closid: u16) {
    let v = (rmid as u64) | ((closid as u64) << 32);
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_PQR_ASSOC, v);
    }
}

/// Read a monitoring event for `rmid`. Returns the
/// `IA32_QM_CTR` value (bit 63 clear if unavailable, else event
/// count).
///
/// # Safety
/// CPL = 0; RDT-M supported.
pub unsafe fn read_event(rmid: u16, evt_id: u32) -> u64 {
    let sel = (evt_id as u64) | ((rmid as u64) << 32);
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_QM_EVTSEL, sel);
    }
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_QM_CTR) }
}

/// Program the CAT mask for a CLOSID on L3.
///
/// # Safety
/// CPL = 0; L3-CAT supported.
pub unsafe fn write_l3_mask(closid: u16, mask: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_L3_QOS_BASE + closid as u32, mask);
    }
}

/// Same for L2.
///
/// # Safety
/// CPL = 0; L2-CAT supported.
pub unsafe fn write_l2_mask(closid: u16, mask: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_L2_QOS_BASE + closid as u32, mask);
    }
}

/// Write MBA throttle as a percentage (0..=100). Higher = more
/// throttle. Hardware quantises to its supported step size.
///
/// # Safety
/// CPL = 0; MBA supported.
pub unsafe fn write_mba_throttle(closid: u16, throttle_pct: u16) {
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_MBA_BASE + closid as u32, throttle_pct as u64);
    }
}
