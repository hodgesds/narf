//! aarch64 SPECRES — speculation-restriction instructions.
//!
//! Spec: `arch/specification/cpu-compute-confidential.md` §3.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

fn id_aa64isar1() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64ISAR1_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64isar1_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Raw `ID_AA64ISAR1_EL1.SPECRES` field (bits[43:40]).
pub fn caps() -> u8 {
    ((id_aa64isar1() >> 40) & 0xF) as u8
}

/// `CFP RCTX, Xt` — clear branch-prediction state for the
/// supplied context. Encoded as `SYS #3, C7, C3, #4, Xt`.
///
/// # Safety
/// EL1; SPECRES supported (`caps() >= 1`).
#[inline]
pub unsafe fn cfp_rctx(ctx: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "sys #3, c7, c3, #4, {}",
            in(reg) ctx,
            options(nostack, preserves_flags),
        );
    }
}
