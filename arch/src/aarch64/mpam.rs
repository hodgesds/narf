//! aarch64 MPAM — Memory Partitioning and Monitoring.
//!
//! Spec: `arch/specification/cpu-telemetry-qos.md` §5.
//!
//! MPAM tags every memory request with `(PARTID, PMG)` so the
//! interconnect can apportion shared resources (LLC, memory
//! bandwidth) per workload class.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64pfr0() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64PFR0_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64pfr0_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

fn id_aa64pfr1() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64PFR1_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64pfr1_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

#[derive(Copy, Clone, Debug, Default)]
pub struct MpamCaps {
    pub supported: bool,
    pub revision:  u8,
    pub frac:      u8,
    pub max_partid:u16,
    pub max_pmg:   u8,
}

pub fn caps() -> MpamCaps {
    let pfr0 = id_aa64pfr0();
    let major = ((pfr0 >> 40) & 0xF) as u8;
    if major == 0 {
        return MpamCaps::default();
    }
    let pfr1 = id_aa64pfr1();
    let frac = ((pfr1 >> 16) & 0xF) as u8;

    // MPAMIDR_EL1 = S3_0_C10_C4_4 — PARTID + PMG ranges.
    let id: u64;
    // SAFETY: MPAMIDR readable when MPAM is implemented.
    unsafe {
        asm!("mrs {}, S3_0_C10_C4_4", out(reg) id, options(nomem, nostack));
    }
    let max_partid = (id & 0xFFFF) as u16;
    let max_pmg    = ((id >> 32) & 0xFF) as u8;

    MpamCaps {
        supported: true,
        revision: major,
        frac,
        max_partid,
        max_pmg,
    }
}

const MPAMEN: u64 = 1 << 63;

fn pack(partid_d: u16, partid_i: u16, pmg_d: u8, pmg_i: u8, enable: bool) -> u64 {
    let mut v = (partid_d as u64)
              | ((partid_i as u64) << 16)
              | ((pmg_d as u64) << 32)
              | ((pmg_i as u64) << 40);
    if enable { v |= MPAMEN; }
    v
}

/// Write `MPAM0_EL1` (raw `S3_0_C10_C5_1`).
///
/// # Safety
/// EL1; MPAM supported.
pub unsafe fn write_mpam0(partid_d: u16, partid_i: u16, pmg_d: u8, pmg_i: u8, enable: bool) {
    let v = pack(partid_d, partid_i, pmg_d, pmg_i, enable);
    // SAFETY: caller-asserted.
    unsafe {
        asm!("msr S3_0_C10_C5_1, {}", in(reg) v, options(nostack, preserves_flags));
    }
}

/// Write `MPAM1_EL1` (raw `S3_0_C10_C5_0`).
///
/// # Safety
/// EL1; MPAM supported.
pub unsafe fn write_mpam1(partid_d: u16, partid_i: u16, pmg_d: u8, pmg_i: u8, enable: bool) {
    let v = pack(partid_d, partid_i, pmg_d, pmg_i, enable);
    // SAFETY: caller-asserted.
    unsafe {
        asm!("msr S3_0_C10_C5_0, {}", in(reg) v, options(nostack, preserves_flags));
    }
}
