//! aarch64 LSE / LSE128 + RCPC / RCPC2 / RCPC3 caps.
//!
//! Spec: `arch/specification/cpu-atomics-mitigations.md` §3 + §4.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64isar0() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64ISAR0_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64isar0_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

fn id_aa64isar1() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64ISAR1_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64isar1_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Raw `ID_AA64ISAR0_EL1.Atomic` field (bits[23:20]).
pub fn caps() -> u8 {
    ((id_aa64isar0() >> 20) & 0xF) as u8
}

pub fn lse_supported() -> bool { caps() >= 1 }
pub fn lse128_supported() -> bool { caps() >= 2 }

/// Raw `ID_AA64ISAR1_EL1.LRCPC` field (bits[23:20]).
pub fn rcpc_caps() -> u8 {
    ((id_aa64isar1() >> 20) & 0xF) as u8
}

pub fn rcpc_supported() -> bool { rcpc_caps() >= 1 }
pub fn rcpc2_supported() -> bool { rcpc_caps() >= 2 }
pub fn rcpc3_supported() -> bool { rcpc_caps() >= 3 }
