//! aarch64 RNDR / RNDRRS — architectural hardware RNG.
//!
//! Spec: `arch/specification/cpu-arch-extensions.md` §4.

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

/// `true` iff `ID_AA64ISAR0_EL1.RNDR` (bits[63:60]) ≥ 1.
pub fn supported() -> bool {
    ((id_aa64isar0() >> 60) & 0xF) != 0
}

/// Read `RNDR` (raw `S3_3_C2_C4_0`). Returns `None` on entropy
/// starvation (`NZCV.C = 0`).
pub fn try_rndr() -> Option<u64> {
    if !supported() {
        return None;
    }
    let v: u64;
    let ok: u64;
    // SAFETY: RNDR is unprivileged + side-effect-free; entropy
    // starvation is signalled via NZCV.C, which we capture with
    // cset.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!(
            "mrs {v}, S3_3_C2_C4_0",
            "cset {ok}, cs",
            v  = out(reg) v,
            ok = out(reg) ok,
            options(nostack),
        );
    }
    if ok == 1 {
        Some(v)
    } else {
        None
    }
}

/// Read `RNDRRS` (raw `S3_3_C2_C4_1`) — reseed-grade entropy.
pub fn try_rndrrs() -> Option<u64> {
    if !supported() {
        return None;
    }
    let v: u64;
    let ok: u64;
    // SAFETY: same as `try_rndr`.
    unsafe {
        asm!(
            "mrs {v}, S3_3_C2_C4_1",
            "cset {ok}, cs",
            v  = out(reg) v,
            ok = out(reg) ok,
            options(nostack),
        );
    }
    if ok == 1 {
        Some(v)
    } else {
        None
    }
}
