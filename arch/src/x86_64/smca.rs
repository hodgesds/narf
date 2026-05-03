//! AMD SMCA — Scalable MCA.
//!
//! Spec: `arch/specification/modern-cpu.md` §4.
//!
//! Zen+ silicon ships an extended per-bank register set in the
//! `MSR 0xC000_2000+` window (in addition to the legacy
//! `MSR 0x400+` MCA banks the existing `mce` module decodes).
//! This module surfaces those extended registers — the IPID,
//! syndrome, deferred-error status, and per-bank config — so
//! the MCE handler can log Zen-class errors with full fidelity.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::rdmsr;

const SMCA_BASE: u32 = 0xC000_2000;
/// Stride between bank `i`'s register block and bank `i+1`'s.
const BANK_STRIDE: u32 = 0x10;

// Per-bank offsets within the SMCA register block.
const REG_CONFIG: u32 = 0x2;
const REG_IPID:   u32 = 0x3;
const REG_DESTAT: u32 = 0x7;
const REG_SYND:   u32 = 0x6;
const REG_MISC0:  u32 = 0x4;

/// `true` iff CPUID(0x80000007).EBX[3] is set (SMCA).
pub fn supported() -> bool {
    // SAFETY: leaf 0x80000000 always defined.
    let max_ext = unsafe { cpuid(0x8000_0000, 0).0 };
    if max_ext < 0x8000_0007 { return false; }
    // SAFETY: extended leaf 0x8000_0007 valid.
    let (_, ebx, _, _) = unsafe { cpuid(0x8000_0007, 0) };
    ebx & (1 << 3) != 0
}

/// Decoded `MCi_IPID` per AMD APM Vol 2 "Machine Check Architecture".
#[derive(Copy, Clone, Debug, Default)]
pub struct SmcaBankInfo {
    pub instance_id: u16,
    pub hardware_id: u16,
    pub mca_type:    u8,
}

impl SmcaBankInfo {
    pub fn decode(raw: u64) -> Self {
        Self {
            instance_id: (raw & 0xFFFF) as u16,
            hardware_id: ((raw >> 16) & 0xFFFF) as u16,
            mca_type:    ((raw >> 44) & 0xF)    as u8,
        }
    }
}

/// SMCA bank-type enumeration. Numbering matches the
/// `MCi_IPID.McaType` field's encoding for Zen-family.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BankType {
    Ls,    // Load-Store
    If,    // Instruction Fetch
    L2,
    De,    // Decoder
    Ex,    // Execution
    Fp,
    L3,
    Mp5,
    Smu,
    Pb,    // Parameter Block
    Umc,   // Unified Memory Controller
    Pcie,
    Other(u8),
}

impl BankType {
    pub fn from_raw(b: u8) -> Self {
        match b {
            0  => Self::Ls,    1 => Self::If,   2 => Self::L2,   3 => Self::De,
            5  => Self::Ex,    6 => Self::Fp,   7 => Self::L3,   8 => Self::Mp5,
            9  => Self::Smu,  10 => Self::Pb,  11 => Self::Umc, 12 => Self::Pcie,
            o  => Self::Other(o),
        }
    }
}

fn bank_msr(bank: u8, off: u32) -> u32 {
    SMCA_BASE + (bank as u32) * BANK_STRIDE + off
}

/// Read the bank-config MSR (`MCi_CONFIG`).
///
/// # Safety
/// CPL = 0; SMCA supported; `bank` < architectural bank count.
pub unsafe fn read_config(bank: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(bank_msr(bank, REG_CONFIG)) }
}

/// Read the IPID (Instance + Hardware id + bank type).
///
/// # Safety
/// Same as `read_config`.
pub unsafe fn read_ipid(bank: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(bank_msr(bank, REG_IPID)) }
}

/// Read the syndrome.
///
/// # Safety
/// Same as `read_config`.
pub unsafe fn read_synd(bank: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(bank_msr(bank, REG_SYND)) }
}

/// Read the deferred-error status.
///
/// # Safety
/// Same as `read_config`.
pub unsafe fn read_destat(bank: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(bank_msr(bank, REG_DESTAT)) }
}

/// Read the extended MISC0 register.
///
/// # Safety
/// Same as `read_config`.
pub unsafe fn read_misc0(bank: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(bank_msr(bank, REG_MISC0)) }
}

/// Convenience: decode the IPID for `bank` into a `SmcaBankInfo`
/// + a `BankType`.
///
/// # Safety
/// CPL = 0; SMCA supported.
pub unsafe fn bank_info(bank: u8) -> (SmcaBankInfo, BankType) {
    // SAFETY: caller-asserted.
    let raw = unsafe { read_ipid(bank) };
    let info = SmcaBankInfo::decode(raw);
    let kind = BankType::from_raw(info.mca_type);
    (info, kind)
}
