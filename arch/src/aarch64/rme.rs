//! aarch64 RME — Realm Management Extension.
//!
//! Spec: `arch/specification/cpu-compute-confidential.md` §2.
//!
//! v0.1 surfaces detection only. RME state-management lives in
//! the Realm Management Monitor (RMM) at EL3 and is reached
//! via SMC; the OS at EL1 can confirm presence but cannot
//! transition itself into a Realm.

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

/// Raw `ID_AA64PFR0_EL1.RME` field (bits[55:52]).
pub fn caps() -> u8 {
    ((id_aa64pfr0() >> 52) & 0xF) as u8
}

pub fn supported() -> bool {
    caps() != 0
}
