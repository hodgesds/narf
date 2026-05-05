//! aarch64 GCS — Guarded Control Stack.
//!
//! Spec: `arch/specification/cpu-arch-extensions.md` §3.
//!
//! GCS gives EL0 / EL1 a separate write-protected stack of
//! return targets, pushed implicitly on `BL` and checked on
//! `RET`. The CET-SHSTK analogue.

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

/// Raw `ID_AA64PFR1_EL1.GCS` field (bits[47:44]).
pub fn caps() -> u8 {
    ((id_aa64pfr1() >> 44) & 0xF) as u8
}

const GCSCR_PCRSEL:  u64 = 1 << 0;
const GCSCR_RVCHKEN: u64 = 1 << 1;
const GCSCR_EX:      u64 = 1 << 2;
const GCSCR_STREN:   u64 = 1 << 3;

fn read_gcscr_el1() -> u64 {
    let v: u64;
    // SAFETY: GCSCR_EL1 readable when GCS present.
    unsafe {
        asm!("mrs {}, S3_0_C2_C5_0", out(reg) v, options(nomem, nostack));
    }
    v
}

fn write_gcscr_el1(v: u64) {
    // SAFETY: GCSCR_EL1 writable at EL1 when GCS present.
    unsafe {
        asm!(
            "msr S3_0_C2_C5_0, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

fn read_gcscre0_el1() -> u64 {
    let v: u64;
    // SAFETY: GCSCRE0_EL1 readable.
    unsafe {
        asm!("mrs {}, S3_0_C2_C5_2", out(reg) v, options(nomem, nostack));
    }
    v
}

fn write_gcscre0_el1(v: u64) {
    // SAFETY: GCSCRE0_EL1 writable at EL1.
    unsafe {
        asm!(
            "msr S3_0_C2_C5_2, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// Enable EL1 GCS with the requested checks.
///
/// # Safety
/// EL1; GCS supported; the per-task EL1 GCS region has been
/// allocated + `GCSPR_EL1` programmed.
pub unsafe fn enable_el1(rvcheck: bool, exception_push: bool) {
    let mut v = read_gcscr_el1() | GCSCR_PCRSEL | GCSCR_STREN;
    if rvcheck        { v |= GCSCR_RVCHKEN; }
    if exception_push { v |= GCSCR_EX; }
    write_gcscr_el1(v);
}

/// Enable EL0 GCS via `GCSCRE0_EL1`.
///
/// # Safety
/// EL1; GCS supported; userspace GCSPR_EL0 has been programmed
/// for the current task.
pub unsafe fn enable_el0(rvcheck: bool) {
    let mut v = read_gcscre0_el1() | GCSCR_PCRSEL | GCSCR_STREN;
    if rvcheck { v |= GCSCR_RVCHKEN; }
    write_gcscre0_el1(v);
}

/// # Safety
/// EL1; GCS supported.
pub unsafe fn disable_el1() {
    write_gcscr_el1(read_gcscr_el1() & !(GCSCR_PCRSEL | GCSCR_STREN | GCSCR_RVCHKEN | GCSCR_EX));
}

/// # Safety
/// EL1; GCS supported.
pub unsafe fn disable_el0() {
    write_gcscre0_el1(read_gcscre0_el1() & !(GCSCR_PCRSEL | GCSCR_STREN | GCSCR_RVCHKEN));
}

/// Read `GCSPR_EL1` (raw `S3_0_C2_C5_1`).
///
/// # Safety
/// EL1; GCS supported.
pub unsafe fn read_gcspr_el1() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_0_C2_C5_1", out(reg) v, options(nomem, nostack));
    }
    v
}

pub unsafe fn write_gcspr_el1(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_0_C2_C5_1, {}",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// Read `GCSPR_EL0` (raw `S3_3_C2_C5_1`). Accessible from EL1.
///
/// # Safety
/// EL1; GCS supported.
pub unsafe fn read_gcspr_el0() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_3_C2_C5_1", out(reg) v, options(nomem, nostack));
    }
    v
}

pub unsafe fn write_gcspr_el0(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_3_C2_C5_1, {}",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}
