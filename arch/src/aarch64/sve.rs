//! aarch64 SVE / SVE2 — Scalable Vector Extension.
//!
//! Spec: `arch/specification/cpu-perf-niche.md` §6.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

#[derive(Copy, Clone, Debug, Default)]
pub struct SveCaps {
    pub sve: bool,
    pub sve2: bool,
    pub sve21: bool,
}

fn id_aa64pfr0() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64PFR0_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, id_aa64pfr0_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

fn id_aa64zfr0() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64ZFR0_EL1 readable at EL1 when SVE present.
    // Reading without SVE raises UNDEF — caller must gate. Raw
    // encoding `S3_0_C0_C4_4` because the assembler in
    // aarch64-unknown-none lacks +sve target-feature awareness.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        asm!("mrs {}, S3_0_C0_C4_4", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Read `ZCR_EL1` (raw `S3_0_C1_C2_0`).
///
/// # Safety
/// SVE present + `CPACR_EL1.ZEN` allows EL1 access.
pub unsafe fn read_zcr_el1() -> u64 {
    let v: u64;
    // SAFETY: caller-asserted.
    unsafe {
        asm!("mrs {}, S3_0_C1_C2_0", out(reg) v, options(nomem, nostack));
    }
    v
}

/// Write `ZCR_EL1`.
///
/// # Safety
/// As `read_zcr_el1`.
pub unsafe fn write_zcr_el1(v: u64) {
    // SAFETY: caller-asserted.
    unsafe {
        asm!(
            "msr S3_0_C1_C2_0, {}",
            "isb",
            in(reg) v,
            options(nostack, preserves_flags),
        );
    }
}

/// Decode SVE caps. Reads only ID-group registers — does **not**
/// touch `ZCR_EL1`, so it is safe to call before
/// `CPACR_EL1.ZEN` has been opened.
pub fn caps() -> SveCaps {
    let pfr0 = id_aa64pfr0();
    let sve_field = (pfr0 >> 32) & 0xF;
    if sve_field == 0 {
        return SveCaps::default();
    }
    let zfr0 = id_aa64zfr0();
    let svever = (zfr0 & 0xF) as u8;
    SveCaps {
        sve: true,
        sve2: svever >= 1,
        sve21: svever >= 2,
    }
}

/// Probe the hardware-max vector length in bits. Writes
/// `ZCR_EL1.LEN = 0xF`, reads back the clamped value, restores
/// the previous setting. Returns 0 on cores without SVE.
///
/// # Safety
/// SVE present per `caps().sve`; CPACR.ZEN open. Caller has
/// pinned the CPU (the result is per-CPU).
pub unsafe fn probe_max_vl_bits() -> u16 {
    if !caps().sve {
        return 0;
    }
    // SAFETY: caller-asserted.
    unsafe {
        let prev = read_zcr_el1();
        write_zcr_el1((prev & !0xF) | 0xF);
        let after = read_zcr_el1();
        write_zcr_el1(prev);
        let len = (after & 0xF) as u16;
        (len + 1) * 128
    }
}

/// Pin the per-EL1 vector length.
///
/// # Safety
/// SVE present, CPACR.ZEN open, `bits` is a multiple of 128 not
/// exceeding `probe_max_vl_bits()`.
pub unsafe fn set_vl_bits(bits: u16) {
    let len = (bits / 128).saturating_sub(1) & 0xF;
    // SAFETY: caller-asserted.
    unsafe {
        let prev = read_zcr_el1();
        write_zcr_el1((prev & !0xF) | (len as u64));
    }
}
