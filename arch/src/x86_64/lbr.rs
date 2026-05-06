//! LBR — Last Branch Records.
//!
//! Spec: `observability/specification/perfmon.md` §2.
//!
//! LBR is a hardware-managed ring of recent branches. The ring
//! depth varies by CPU generation (4 / 8 / 16 / 32 entries);
//! NARF probes the depth via the family/model byte and uses
//! the Skylake+ MSR base when supported.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr, wrmsr};

pub const MSR_IA32_DEBUGCTL: u32 = 0x1D9;
pub const MSR_LBR_TOS: u32 = 0x1DD;
pub const MSR_LBR_SELECT: u32 = 0x1C8;
/// Skylake+ LBR FROM base (32 entries: 0x680..0x69F).
pub const MSR_LBR_FROM_BASE_SKL: u32 = 0x680;
/// Skylake+ LBR TO base (32 entries: 0x6C0..0x6DF).
pub const MSR_LBR_TO_BASE_SKL: u32 = 0x6C0;
/// Pre-Skylake LBR FROM base (16 entries: 0x680 wasn't yet used).
pub const MSR_LBR_FROM_BASE_LEGACY: u32 = 0x40;
pub const MSR_LBR_TO_BASE_LEGACY: u32 = 0x60;

const DEBUGCTL_LBR: u64 = 1 << 0;

#[derive(Copy, Clone, Debug, Default)]
pub struct LbrCaps {
    pub n_entries: u8,
    pub from_base: u32,
    pub to_base: u32,
}

/// Family/model classification helper. Returns the LBR ring depth
/// we expect for this CPU. The Intel SDM's enumeration is
/// model-specific; the heuristic below covers Pentium Pro through
/// Sapphire Rapids:
///
///   * Family 0x06, model >= 0x4E (Skylake+) — 32 entries
///   * Family 0x06, model >= 0x1A (Nehalem)  — 16 entries
///   * Family 0x06, model <  0x1A (Core)     —  8 entries
///   * Otherwise (P4 / non-Intel)            —  4 entries
fn n_entries_for_model() -> u8 {
    // SAFETY: leaf 1 always defined.
    let (eax, _, _, _) = unsafe { cpuid(1, 0) };
    let family = ((eax >> 8) & 0xF) + ((eax >> 20) & 0xFF);
    let model = ((eax >> 4) & 0xF) | (((eax >> 16) & 0xF) << 4);
    if family != 0x06 {
        return 4;
    }
    if model >= 0x4E {
        32
    } else if model >= 0x1A {
        16
    } else {
        8
    }
}

pub fn caps() -> LbrCaps {
    let n = n_entries_for_model();
    let (from, to) = if n >= 16 {
        (MSR_LBR_FROM_BASE_SKL, MSR_LBR_TO_BASE_SKL)
    } else {
        (MSR_LBR_FROM_BASE_LEGACY, MSR_LBR_TO_BASE_LEGACY)
    };
    LbrCaps {
        n_entries: n,
        from_base: from,
        to_base: to,
    }
}

/// Enable LBR recording with the given filter mask
/// (`MSR_LBR_SELECT`).
///
/// # Safety
/// CPL = 0.
pub unsafe fn enable(filter: u32) {
    // SAFETY: caller-asserted.
    unsafe {
        wrmsr(MSR_LBR_SELECT, filter as u64);
    }
    // SAFETY: same.
    let dc = unsafe { rdmsr(MSR_IA32_DEBUGCTL) };
    // SAFETY: same.
    unsafe {
        wrmsr(MSR_IA32_DEBUGCTL, dc | DEBUGCTL_LBR);
    }
}

/// Disable LBR recording (clears `IA32_DEBUGCTL.LBR`).
///
/// # Safety
/// CPL = 0.
pub unsafe fn disable() {
    // SAFETY: caller-asserted.
    let dc = unsafe { rdmsr(MSR_IA32_DEBUGCTL) };
    // SAFETY: same.
    unsafe {
        wrmsr(MSR_IA32_DEBUGCTL, dc & !DEBUGCTL_LBR);
    }
}

/// Read entry `idx` as `(from, to)` linear addresses.
///
/// # Safety
/// CPL = 0; `idx < caps().n_entries`.
pub unsafe fn read_pair(idx: u8) -> (u64, u64) {
    let c = caps();
    // SAFETY: caller-asserted.
    let from = unsafe { rdmsr(c.from_base + idx as u32) };
    // SAFETY: same.
    let to = unsafe { rdmsr(c.to_base + idx as u32) };
    (from, to)
}

/// Read the most-recent-record index (`MSR_LBR_TOS`).
///
/// # Safety
/// CPL = 0.
pub unsafe fn read_tos() -> u8 {
    // SAFETY: caller-asserted.
    (unsafe { rdmsr(MSR_LBR_TOS) } & 0xFF) as u8
}
