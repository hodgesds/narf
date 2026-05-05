//! Intel TME / MKTME — Total Memory Encryption.
//!
//! Spec: `arch/specification/cpu-mem-encrypt-virt.md` §1.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_TME_CAPABILITY: u32 = 0x981;
pub const MSR_IA32_TME_ACTIVATE:   u32 = 0x982;

pub const TME_CAPS_AES_XTS_128:           u64 = 1 << 0;
pub const TME_CAPS_AES_XTS_128_INTEGRITY: u64 = 1 << 1;
pub const TME_CAPS_AES_XTS_256:           u64 = 1 << 2;

pub const TME_ACTIVATE_LOCK:   u64 = 1 << 0;
pub const TME_ACTIVATE_ENABLE: u64 = 1 << 1;
pub const TME_ACTIVATE_KEY_SELECT_HW: u64 = 1 << 4;
pub const TME_ACTIVATE_SAVE_KEY_FOR_STANDBY: u64 = 1 << 5;

#[derive(Copy, Clone, Debug, Default)]
pub struct TmeCaps {
    pub aes_xts_128:           bool,
    pub aes_xts_128_integrity: bool,
    pub aes_xts_256:           bool,
    pub max_keyid_bits:        u8,
    pub max_keys:              u16,
}

/// `true` iff CPUID(7, 0).ECX[13] is set.
pub fn supported() -> bool {
    // SAFETY: leaf 0 always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 7 { return false; }
    // SAFETY: leaf 7 valid.
    let (_, _, ecx, _) = unsafe { cpuid(7, 0) };
    ecx & (1 << 13) != 0
}

/// # Safety
/// CPL = 0; TME supported.
pub unsafe fn read_caps() -> TmeCaps {
    // SAFETY: caller-asserted.
    let raw = unsafe { rdmsr(MSR_IA32_TME_CAPABILITY) };
    decode_caps(raw)
}

pub fn decode_caps(raw: u64) -> TmeCaps {
    TmeCaps {
        aes_xts_128:           raw & TME_CAPS_AES_XTS_128 != 0,
        aes_xts_128_integrity: raw & TME_CAPS_AES_XTS_128_INTEGRITY != 0,
        aes_xts_256:           raw & TME_CAPS_AES_XTS_256 != 0,
        max_keyid_bits:        ((raw >> 32) & 0xF) as u8,
        max_keys:              ((raw >> 36) & 0x7FFF) as u16,
    }
}

/// # Safety
/// CPL = 0; TME supported.
pub unsafe fn read_activate() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { rdmsr(MSR_IA32_TME_ACTIVATE) }
}

/// # Safety
/// CPL = 0; TME supported; `v` matches the architectural format.
/// Once the LOCK bit is set hardware rejects further writes
/// until the next reset.
pub unsafe fn write_activate(v: u64) {
    // SAFETY: caller-asserted.
    unsafe { wrmsr(MSR_IA32_TME_ACTIVATE, v); }
}

pub fn locked(activate: u64) -> bool {
    activate & TME_ACTIVATE_LOCK != 0
}
