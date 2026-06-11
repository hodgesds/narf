//! aarch64 FEAT_S1PIE / FEAT_S2PIE — Permission Indirect Encoding.
//!
//! Spec: `arch/specification/cpu-atomics-mitigations.md` §5.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64mmfr3() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64MMFR3_EL1 readable at EL1 (raw S3_0_C0_C7_3
    // — older LLVM doesn't carry the named alias on plain
    // aarch64-unknown-none).
    unsafe {
        asm!("mrs {}, S3_0_C0_C7_3", out(reg) v, options(nomem, nostack));
    }
    v
}

#[derive(Copy, Clone, Debug, Default)]
pub struct PieCaps {
    pub s1pie: bool,
    pub s2pie: bool,
}

pub fn caps() -> PieCaps {
    let v = id_aa64mmfr3();
    PieCaps {
        // ID_AA64MMFR3_EL1 layout (DDI0487 K.b):
        //   bits[3:0]  = S2POE
        //   bits[7:4]  = S1POE
        //   bits[11:8] = S2PIE
        //   bits[15:12] = S1PIE
        s1pie: ((v >> 12) & 0xF) >= 1,
        s2pie: ((v >> 8) & 0xF) >= 1,
    }
}

/// `PIR_EL1` (raw `S3_0_C10_C2_3`).
///
/// # Safety
/// EL1; FEAT_S1PIE supported.
pub unsafe fn read_pir_el1() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_0_C10_C2_3", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Write `PIR_EL1` (raw `S3_0_C10_C2_3`).
///
/// # Safety
/// EL1; FEAT_S1PIE supported; an `isb` is issued to ensure the
/// new permission-indirection table takes effect.
pub unsafe fn write_pir_el1(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_0_C10_C2_3, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// `PIRE0_EL1` (raw `S3_0_C10_C2_2`).
///
/// # Safety
/// EL1; FEAT_S1PIE supported.
pub unsafe fn read_pire0_el1() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_0_C10_C2_2", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Write `PIRE0_EL1` (raw `S3_0_C10_C2_2`).
///
/// # Safety
/// EL1; FEAT_S1PIE supported; an `isb` is issued to ensure the
/// new EL0 permission-indirection table takes effect.
pub unsafe fn write_pire0_el1(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_0_C10_C2_2, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}
