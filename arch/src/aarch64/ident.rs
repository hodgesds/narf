//! aarch64 CPU identification — MIDR_EL1 + REVIDR_EL1 decode.
//!
//! Spec: `arch/specification/cpu-info-errata.md` §5.1.

#![cfg(target_arch = "aarch64")]
#![allow(dead_code)]

use core::arch::asm;

#[derive(Copy, Clone, Debug)]
pub struct AarchIdent {
    pub implementer: u8,
    pub variant:     u8,
    pub part:        u16,
    pub revision:    u8,
    pub raw:         u64,
}

pub fn ident() -> AarchIdent {
    let raw: u64;
    // SAFETY: MIDR_EL1 readable at EL1 unconditionally.
    unsafe {
        asm!("mrs {}, midr_el1", out(reg) raw, options(nomem, nostack));
    }
    AarchIdent {
        implementer: ((raw >> 24) & 0xFF) as u8,
        variant:     ((raw >> 20) & 0xF)  as u8,
        part:        ((raw >> 4)  & 0xFFF) as u16,
        revision:    (raw & 0xF) as u8,
        raw,
    }
}

pub fn revidr() -> u64 {
    let v: u64;
    // SAFETY: REVIDR_EL1 readable at EL1.
    unsafe {
        asm!("mrs {}, revidr_el1", out(reg) v, options(nomem, nostack));
    }
    v
}

pub fn implementer_name(implementer: u8) -> &'static str {
    match implementer {
        0x41 => "Arm",
        0x42 => "Broadcom",
        0x43 => "Cavium",
        0x44 => "DEC",
        0x46 => "Fujitsu",
        0x49 => "Infineon",
        0x4D => "Motorola/Freescale",
        0x4E => "NVIDIA",
        0x50 => "AppliedMicro",
        0x51 => "Qualcomm",
        0x53 => "Samsung",
        0x56 => "Marvell",
        0x61 => "Apple",
        0x66 => "Faraday",
        0x69 => "Intel",
        0xC0 => "Ampere",
        _    => "Unknown",
    }
}
