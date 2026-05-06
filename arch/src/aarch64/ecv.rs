//! aarch64 ECV — Enhanced Counter Virtualization.
//!
//! Spec: `arch/specification/cpu-mem-encrypt-virt.md` §3.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64mmfr0() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64MMFR0_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64mmfr0_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Raw `ID_AA64MMFR0_EL1.ECV` field (bits[63:60]).
pub fn caps() -> u8 {
    ((id_aa64mmfr0() >> 60) & 0xF) as u8
}

pub fn supported() -> bool {
    caps() >= 1
}

/// `true` iff CNTPOFF support is present (ECV ≥ 2).
pub fn cntpoff_supported() -> bool {
    caps() >= 2
}
