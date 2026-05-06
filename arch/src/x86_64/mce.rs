//! Machine Check Architecture (MCA / MCE) — clean-room.
//!
//! Reference: **Intel SDM Vol 3 Chapter 16** ("Machine-Check
//! Architecture") + **AMD APM Vol 2 §9.5** (the AMD MCA layout
//! is structurally compatible with Intel for the bank registers
//! we read, modulo a few vendor-specific status bits we leave
//! out).
//!
//! ## Register set
//!
//! Per-bank (bank `i` = 0, 1, ..., `MCG_CAP.COUNT-1`):
//!
//! | MSR        | name           | description                      |
//! |------------|----------------|----------------------------------|
//! | 0x400+4*i  | MCi_CTL        | Bank enable bitmap               |
//! | 0x401+4*i  | MCi_STATUS     | Per-error status (W1C)           |
//! | 0x402+4*i  | MCi_ADDR       | Faulting linear/phys address     |
//! | 0x403+4*i  | MCi_MISC       | Implementation-specific detail   |
//!
//! Global:
//!
//! | MSR    | name      | description                                |
//! |--------|-----------|--------------------------------------------|
//! | 0x179  | MCG_CAP   | bits[7:0] = bank count, bits 8/9/10/11 control bits |
//! | 0x17A  | MCG_STATUS | RIPV / EIPV / MCIP                          |
//!
//! Stage cut: `mcg_cap`/`mcg_status` decode + per-bank read +
//! `MciStatus` decoder. The `#MC` IDT vector handler itself is
//! a frame/ concern (the trap prologue lives there); this
//! module supplies the decode-and-log surface that handler will
//! call.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_MCG_CAP: u32 = 0x179;
pub const MSR_MCG_STATUS: u32 = 0x17A;

const MSR_MCi_CTL_BASE: u32 = 0x400;
const MSR_MCi_STATUS_BASE: u32 = 0x401;
const MSR_MCi_ADDR_BASE: u32 = 0x402;
const MSR_MCi_MISC_BASE: u32 = 0x403;

/// Decoded `MCG_CAP`. `count` is the number of MC banks; the
/// other bits expose threshold / control hints.
#[derive(Copy, Clone, Debug)]
pub struct McgCap {
    pub count: u8,
    pub mcg_ctl_p: bool,
    pub mcg_ext_p: bool,
    pub mcg_cmci_p: bool,
    pub mcg_tes_p: bool,
    pub mcg_ext_count: u8,
    pub mcg_lmce_p: bool,
}

impl McgCap {
    pub fn decode(raw: u64) -> Self {
        Self {
            count: (raw & 0xFF) as u8,
            mcg_ctl_p: raw & (1 << 8) != 0,
            mcg_ext_p: raw & (1 << 9) != 0,
            mcg_cmci_p: raw & (1 << 10) != 0,
            mcg_tes_p: raw & (1 << 11) != 0,
            mcg_ext_count: ((raw >> 16) & 0xFF) as u8,
            mcg_lmce_p: raw & (1 << 27) != 0,
        }
    }
}

/// MCG_STATUS bits.
pub const MCG_STATUS_RIPV: u64 = 1 << 0; // Restart-IP valid.
pub const MCG_STATUS_EIPV: u64 = 1 << 1; // Error-IP valid.
pub const MCG_STATUS_MCIP: u64 = 1 << 2; // MC in progress.
pub const MCG_STATUS_LMCE: u64 = 1 << 3; // Local MCE delivery.

/// Decoded MCi_STATUS bits (SDM Vol 3 §16.3.2.2).
#[derive(Copy, Clone, Debug)]
pub struct MciStatus {
    pub raw: u64,
    /// True if the status entry is valid (bit 63).
    pub valid: bool,
    /// True if the bank logged a fatal/uncorrectable error (bit 61 = UC).
    pub uc: bool,
    /// True if the error is the cause of an MCE (bit 60 = EN).
    pub en: bool,
    /// True if the error was successfully signalled to software (bit 59 = MISCV).
    pub miscv: bool,
    /// True if MCi_ADDR holds a valid address (bit 58 = ADDRV).
    pub addrv: bool,
    /// True if the bank state was corrected (bit 57 = PCC: processor-context corrupt).
    pub pcc: bool,
    /// MCA error code (bits[15:0]) — vendor-specific.
    pub mca_code: u16,
    /// Model-specific error code (bits[31:16]).
    pub model_code: u16,
    /// Bit 62 = OVER (overflow).
    pub overflow: bool,
}

impl MciStatus {
    pub fn decode(raw: u64) -> Self {
        Self {
            raw,
            valid: raw & (1 << 63) != 0,
            uc: raw & (1 << 61) != 0,
            en: raw & (1 << 60) != 0,
            miscv: raw & (1 << 59) != 0,
            addrv: raw & (1 << 58) != 0,
            pcc: raw & (1 << 57) != 0,
            overflow: raw & (1 << 62) != 0,
            mca_code: (raw & 0xFFFF) as u16,
            model_code: ((raw >> 16) & 0xFFFF) as u16,
        }
    }
}

/// Read MCG_CAP.
///
/// # Safety
/// CPL = 0; MCA architecturally available iff `CPUID(1).EDX[14]` is set.
pub unsafe fn mcg_cap() -> McgCap {
    // SAFETY: caller-asserted CPL=0; MCG_CAP exists when MCA does.
    let raw = unsafe { rdmsr(MSR_MCG_CAP) };
    McgCap::decode(raw)
}

/// Read MCG_STATUS.
///
/// # Safety
/// Same as `mcg_cap`.
pub unsafe fn mcg_status() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_MCG_STATUS) }
}

/// Read MCi_STATUS for bank `i`. Returns `None` if `i` is out of
/// range relative to the architectural bank count.
///
/// # Safety
/// CPL = 0. `i` must be `< mcg_cap().count`; the SDM warns that
/// reading past the architectural count is undefined.
pub unsafe fn mci_status(i: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_MCi_STATUS_BASE + 4 * i as u32) }
}

/// Read MCi_ADDR for bank `i`.
///
/// # Safety
/// Same as `mci_status`. The address is only meaningful when the
/// matching MCi_STATUS has ADDRV (bit 58) set.
pub unsafe fn mci_addr(i: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_MCi_ADDR_BASE + 4 * i as u32) }
}

/// Read MCi_MISC for bank `i`.
///
/// # Safety
/// Same as `mci_status`. Only meaningful when MISCV is set.
pub unsafe fn mci_misc(i: u8) -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_MCi_MISC_BASE + 4 * i as u32) }
}

/// Clear (write-1-clear) MCi_STATUS for bank `i`. Done after the
/// `#MC` handler has logged the error.
///
/// # Safety
/// CPL = 0; clearing a bank that wasn't latched is benign.
pub unsafe fn clear_mci_status(i: u8) {
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_MCi_STATUS_BASE + 4 * i as u32, 0);
    }
}

/// Initialise MCA: enable every architectural bank by writing all-1s
/// to each `MCi_CTL`, and clear any latched `MCi_STATUS`.
///
/// # Safety
/// Boot-time CPL=0; MCA support already verified via CPUID.
pub unsafe fn init() {
    // SAFETY: caller-asserted.
    let cap = unsafe { mcg_cap() };
    for i in 0..cap.count {
        // Enable every error in the bank.
        // SAFETY: CPL=0.
        unsafe {
            wrmsr(MSR_MCi_CTL_BASE + 4 * i as u32, !0u64);
        }
        // SAFETY: same.
        unsafe {
            wrmsr(MSR_MCi_STATUS_BASE + 4 * i as u32, 0);
        }
    }
}

/// `true` iff MCA is reported by CPUID.
pub fn is_supported() -> bool {
    // SAFETY: CPUID leaf 1 always defined.
    let (_, _, _, edx) = unsafe { cpuid(1, 0) };
    edx & (1 << 14) != 0 // MCA bit
}

/// Snapshot of every populated bank — returned by the `#MC`
/// handler's decode-and-log step.
#[derive(Debug, Default)]
pub struct McSnapshot {
    pub mcg_status: u64,
    pub banks: [Option<McBank>; 32],
}

#[derive(Copy, Clone, Debug)]
pub struct McBank {
    pub index: u8,
    pub status: MciStatus,
    pub addr: Option<u64>,
    pub misc: Option<u64>,
}

/// Read every architectural bank, decoded.
///
/// # Safety
/// CPL=0; MCA supported.
pub unsafe fn snapshot() -> McSnapshot {
    let mut s = McSnapshot::default();
    // SAFETY: caller-asserted.
    let cap = unsafe { mcg_cap() };
    // SAFETY: same.
    s.mcg_status = unsafe { mcg_status() };
    let n = (cap.count as usize).min(s.banks.len());
    for i in 0..n {
        // SAFETY: same.
        let raw = unsafe { mci_status(i as u8) };
        let st = MciStatus::decode(raw);
        if !st.valid {
            continue;
        }
        // SAFETY: same.
        let addr = if st.addrv {
            Some(unsafe { mci_addr(i as u8) })
        } else {
            None
        };
        // SAFETY: same.
        let misc = if st.miscv {
            Some(unsafe { mci_misc(i as u8) })
        } else {
            None
        };
        s.banks[i] = Some(McBank {
            index: i as u8,
            status: st,
            addr,
            misc,
        });
    }
    s
}
