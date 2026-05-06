//! aarch64 SME — Scalable Matrix Extension.
//!
//! Spec: `arch/specification/cpu-compute-confidential.md` §1.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64pfr1() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64PFR1_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64pfr1_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

#[derive(Copy, Clone, Debug, Default)]
pub struct SmeCaps {
    pub sme: bool,
    pub sme2: bool,
}

pub fn caps() -> SmeCaps {
    let f = (id_aa64pfr1() >> 24) & 0xF;
    SmeCaps {
        sme: f >= 1,
        sme2: f >= 2,
    }
}

const SVCR_SM: u64 = 1 << 0;
const SVCR_ZA: u64 = 1 << 1;

/// Read `SVCR` (raw `S3_3_C4_C2_2`).
///
/// # Safety
/// EL1; SME supported; CPACR_EL1.SMEN open.
pub unsafe fn read_svcr() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_3_C4_C2_2", out(reg) v, options(nomem, nostack));
    }
    v
}

pub unsafe fn write_svcr(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_3_C4_C2_2, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// Enter streaming mode (SVCR.SM = 1).
///
/// # Safety
/// EL1; SME supported; SMEN open.
pub unsafe fn enter_streaming() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_svcr() } | SVCR_SM;
    unsafe {
        write_svcr(v);
    }
}

pub unsafe fn leave_streaming() {
    let v = unsafe { read_svcr() } & !SVCR_SM;
    unsafe {
        write_svcr(v);
    }
}

/// Enable ZA tile storage (SVCR.ZA = 1).
///
/// # Safety
/// EL1; SME supported; SMEN open.
pub unsafe fn enable_za() {
    let v = unsafe { read_svcr() } | SVCR_ZA;
    unsafe {
        write_svcr(v);
    }
}

pub unsafe fn disable_za() {
    let v = unsafe { read_svcr() } & !SVCR_ZA;
    unsafe {
        write_svcr(v);
    }
}

/// Read `SMCR_EL1` (raw `S3_0_C1_C2_6`) — streaming-mode VL
/// control.
///
/// # Safety
/// EL1; SME supported; SMEN open.
pub unsafe fn read_smcr_el1() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_0_C1_C2_6", out(reg) v, options(nomem, nostack));
    }
    v
}

pub unsafe fn write_smcr_el1(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_0_C1_C2_6, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}
