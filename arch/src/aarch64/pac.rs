//! aarch64 Pointer Authentication (PAC).
//!
//! Spec: `arch/specification/cpu-security.md` §1.
//!
//! PAC stores a cryptographic signature in the upper bits of a
//! pointer. `PAC{IA,IB,DA,DB,GA}` instructions add the signature;
//! `AUT{IA,IB,DA,DB}` verify and strip it. Five 128-bit keys
//! (APIA, APIB, APDA, APDB, APGA) live in MSR-pairs; the OS
//! initialises them at boot and per task switch.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

#[derive(Copy, Clone, Debug, Default)]
pub struct PacCaps {
    pub address_auth: bool,
    pub generic_auth: bool,
    pub enhanced: bool,
}

/// Read `ID_AA64ISAR1_EL1`.
fn id_aa64isar1() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64ISAR1_EL1 readable at EL1 unconditionally.
    unsafe {
        asm!("mrs {}, id_aa64isar1_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

fn id_aa64isar2() -> u64 {
    let v: u64;
    // SAFETY: ID_AA64ISAR2_EL1 readable at EL1 (added v8.7).
    unsafe {
        asm!("mrs {}, id_aa64isar2_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

pub fn caps() -> PacCaps {
    let isar1 = id_aa64isar1();
    let apa = (isar1 >> 4) & 0xF;
    let api = (isar1 >> 8) & 0xF;
    let gpa = (isar1 >> 24) & 0xF;
    let gpi = (isar1 >> 28) & 0xF;
    let isar2 = id_aa64isar2();
    let apa3 = (isar2 >> 12) & 0xF;
    let gpa3 = (isar2 >> 8) & 0xF;
    PacCaps {
        address_auth: apa != 0 || api != 0 || apa3 != 0,
        generic_auth: gpa != 0 || gpi != 0 || gpa3 != 0,
        // FEAT_EPAC = APA / API >= 2.
        enhanced: apa >= 2 || api >= 2,
    }
}

// ── Key write helpers (use raw MSR encodings via asm!) ─────────────

macro_rules! write_key_pair {
    ($name:ident, $low_msr:literal, $high_msr:literal) => {
        /// Write the low + high halves of the corresponding PAC key.
        ///
        /// # Safety
        /// EL1; PAC supported.
        pub unsafe fn $name(low: u64, high: u64) {
            // SAFETY: caller-asserted; raw MSR encoding form is the
            // only way to address the PAC key MSRs from Rust asm.
            unsafe {
                asm!(
                    concat!("msr ", $low_msr,  ", {l}"),
                    concat!("msr ", $high_msr, ", {h}"),
                    "isb",
                    l = in(reg) low,
                    h = in(reg) high,
                    options(nostack, preserves_flags),
                );
            }
        }
    };
}

// PAC key MSRs aren't named in older LLVM aarch64 assemblers, so we
// use the architectural raw S<op0>_<op1>_C<CRn>_C<CRm>_<op2> encoding
// — these always work and decode unambiguously per the Arm ARM.
write_key_pair!(write_apia_key, "S3_0_C2_C1_0", "S3_0_C2_C1_1");
write_key_pair!(write_apib_key, "S3_0_C2_C1_2", "S3_0_C2_C1_3");
write_key_pair!(write_apda_key, "S3_0_C2_C2_0", "S3_0_C2_C2_1");
write_key_pair!(write_apdb_key, "S3_0_C2_C2_2", "S3_0_C2_C2_3");
write_key_pair!(write_apga_key, "S3_0_C2_C3_0", "S3_0_C2_C3_1");

// ── SCTLR_EL1 enable bits ──────────────────────────────────────────

const SCTLR_ENIA: u64 = 1 << 31;
const SCTLR_ENIB: u64 = 1 << 30;
const SCTLR_ENDA: u64 = 1 << 27;
const SCTLR_ENDB: u64 = 1 << 13;

/// Enable PAC instructions for the requested key sets via
/// `SCTLR_EL1`.
///
/// # Safety
/// EL1; PAC supported; the corresponding keys have been
/// installed via `write_*_key`.
pub unsafe fn enable_keys(ia: bool, ib: bool, da: bool, db: bool) {
    let mut sctlr: u64;
    // SAFETY: SCTLR_EL1 is RW at EL1.
    unsafe {
        asm!("mrs {}, sctlr_el1", out(reg) sctlr, options(nomem, nostack));
    }
    if ia {
        sctlr |= SCTLR_ENIA;
    }
    if ib {
        sctlr |= SCTLR_ENIB;
    }
    if da {
        sctlr |= SCTLR_ENDA;
    }
    if db {
        sctlr |= SCTLR_ENDB;
    }
    // SAFETY: same.
    unsafe {
        asm!(
            "msr sctlr_el1, {v}",
            "isb",
            v = in(reg) sctlr,
            options(nostack, preserves_flags),
        );
    }
}
