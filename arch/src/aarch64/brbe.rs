//! aarch64 BRBE — Branch Record Buffer Extension.
//!
//! Spec: `arch/specification/cpu-telemetry-qos.md` §3.
//!
//! BRBE captures up to 64 most-recent taken branches into
//! `BRBSRC<n>_EL1` / `BRBTGT<n>_EL1` / `BRBINF<n>_EL1`. The
//! v0.1 surface lands the control + filter MSRs and the caps
//! decode; the per-record dump path lives in `pmu/`.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64dfr0() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64DFR0_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64dfr0_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Raw `ID_AA64DFR0_EL1.BRBE` field (bits[55:52]).
///
/// | value | meaning             |
/// |-------|---------------------|
/// | 0     | not implemented     |
/// | 1     | BRBE                |
/// | 2     | + BRBE-EL3          |
pub fn caps() -> u8 {
    ((id_aa64dfr0() >> 52) & 0xF) as u8
}

/// `BRBCR_EL1` raw encoding `S2_1_C9_C0_0`.
///
/// # Safety
/// EL1; BRBE supported (`caps() >= 1`).
pub unsafe fn read_brbcr_el1() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S2_1_C9_C0_0", out(reg) v, options(nomem, nostack));
    }
    v
}

pub unsafe fn write_brbcr_el1(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S2_1_C9_C0_0, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// `BRBFCR_EL1` raw encoding `S2_1_C9_C0_1`.
///
/// # Safety
/// EL1; BRBE supported.
pub unsafe fn read_brbfcr_el1() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S2_1_C9_C0_1", out(reg) v, options(nomem, nostack));
    }
    v
}

pub unsafe fn write_brbfcr_el1(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S2_1_C9_C0_1, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

const BRBCR_E1BRE: u64 = 1 << 0;
const BRBCR_E0BRE: u64 = 1 << 1;
const BRBCR_PAUSED: u64 = 1 << 7;

/// Enable branch recording for both EL0 and EL1.
///
/// # Safety
/// EL1; BRBE supported.
pub unsafe fn enable() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_brbcr_el1() } | BRBCR_E1BRE | BRBCR_E0BRE;
    unsafe { write_brbcr_el1(v); }
}

pub unsafe fn disable() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_brbcr_el1() } & !(BRBCR_E1BRE | BRBCR_E0BRE);
    unsafe { write_brbcr_el1(v); }
}

/// Pause recording (`BRBCR.PAUSED`). Useful before draining
/// the BRB.
///
/// # Safety
/// EL1; BRBE supported.
pub unsafe fn freeze() {
    // SAFETY: caller-asserted.
    let v = unsafe { read_brbcr_el1() } | BRBCR_PAUSED;
    unsafe { write_brbcr_el1(v); }
}
