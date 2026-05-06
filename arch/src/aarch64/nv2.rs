//! aarch64 NV / NV2 — Nested Virtualization.
//!
//! Spec: `arch/specification/cpu-mem-encrypt-virt.md` §4.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64mmfr2() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64MMFR2_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64mmfr2_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Raw `ID_AA64MMFR2_EL1.NV` field (bits[27:24]).
pub fn caps() -> u8 {
    ((id_aa64mmfr2() >> 24) & 0xF) as u8
}

pub fn supported() -> bool {
    caps() >= 1
}

pub fn nv2_supported() -> bool {
    caps() >= 2
}
