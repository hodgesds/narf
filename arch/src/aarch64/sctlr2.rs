//! aarch64 FEAT_SCTLR2 — extended SCTLR2_EL1.
//!
//! Spec: `arch/specification/cpu-atomics-mitigations.md` §6.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64mmfr3() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64MMFR3_EL1 readable at EL1 (raw S3_0_C0_C7_3).
    unsafe {
        asm!("mrs {}, S3_0_C0_C7_3", out(reg) v, options(nomem, nostack));
    }
    v
}

/// `true` iff `ID_AA64MMFR3_EL1.SCTLRX` (bits[15:12]) ≥ 1.
pub fn supported() -> bool {
    ((id_aa64mmfr3() >> 12) & 0xF) >= 1
}

/// `SCTLR2_EL1` raw `S3_0_C1_C0_3`.
///
/// # Safety
/// EL1; FEAT_SCTLR2 supported.
pub unsafe fn read_sctlr2_el1() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_0_C1_C0_3", out(reg) v, options(nomem, nostack));
    }
    v
}

pub unsafe fn write_sctlr2_el1(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_0_C1_C0_3, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}
