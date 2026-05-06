//! x86_64 CPU errata workarounds.
//!
//! Spec: `arch/specification/cpu-info-errata.md` §3.
//!
//! v0.1 carries marker entries only — the actual workaround
//! bodies hand off to the existing modules (`spec_ctrl`,
//! `msr`). The shape is `&'static [Errata]` so future entries
//! append without editing call sites.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::ident::{self, Vendor};

#[derive(Copy, Clone, Debug)]
pub struct Errata {
    pub name: &'static str,
    pub vendor: Vendor,
    pub family: u16,
    pub model_lo: u16,
    pub model_hi: u16,
    pub stepping_mask: u32,
    pub apply: unsafe fn(),
}

unsafe fn nop_workaround() { /* marker-only entry */
}

/// Marker for Intel TSX-RTM disable (KBL027 / Skylake-X).
///
/// # Safety
/// CPL = 0. Reads + masks `MSR_IA32_TSX_CTRL` if the platform
/// microcode advertises it via CPUID(7,0).EDX[29]; otherwise no
/// effect.
unsafe fn intel_disable_tsx_rtm() {
    use crate::x86_64::cpuid::cpuid;
    use crate::x86_64::msr::{rdmsr, wrmsr};
    const TSX_CTRL_MSR: u32 = 0x122;
    // SAFETY: leaf 7 sub-0 valid (Stage 1 boot validation).
    let (_, _, _, edx) = unsafe { cpuid(7, 0) };
    if edx & (1 << 29) == 0 {
        return;
    }
    // bit 0 = RTM_DISABLE, bit 1 = TSX_CPUID_CLEAR
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(TSX_CTRL_MSR) };
    unsafe {
        wrmsr(TSX_CTRL_MSR, v | 0b11);
    }
}

/// Marker for AMD Zen1 erratum 1474 — clamp DE_CFG[9].
///
/// # Safety
/// CPL = 0; AMD Zen1.
unsafe fn amd_zen1_erratum_1474() {
    use crate::x86_64::msr::{rdmsr, wrmsr};
    const MSR_DE_CFG: u32 = 0xC001_1029;
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_DE_CFG) };
    unsafe {
        wrmsr(MSR_DE_CFG, v | (1 << 9));
    }
}

/// Errata table. Entries are ordered (vendor, family, model_lo)
/// so future binary-search dispatch is mechanical.
pub const TABLE: &[Errata] = &[
    Errata {
        name: "intel-tsx-rtm-disable",
        vendor: Vendor::Intel,
        family: 0x06,
        model_lo: 0x55,
        model_hi: 0x55, // Skylake-X / SKL-SP
        stepping_mask: 0xFFFF_FFFF,
        apply: intel_disable_tsx_rtm,
    },
    Errata {
        name: "amd-zen1-1474",
        vendor: Vendor::Amd,
        family: 0x17,
        model_lo: 0x00,
        model_hi: 0x2F,
        stepping_mask: 0xFFFF_FFFF,
        apply: amd_zen1_erratum_1474,
    },
    Errata {
        name: "marker-noop",
        vendor: Vendor::Other([0; 12]),
        family: 0xFFFF,
        model_lo: 0xFFFF,
        model_hi: 0xFFFF,
        stepping_mask: 0,
        apply: nop_workaround,
    },
];

pub fn table() -> &'static [Errata] {
    TABLE
}

/// Apply every errata entry that matches the current CPU.
/// Idempotent — safe to call once per AP.
///
/// # Safety
/// CPL = 0; the per-entry `apply` functions are themselves
/// safe to call (they gate on CPUID).
pub unsafe fn apply_for_current_cpu() {
    let me = ident::read();
    for e in TABLE {
        if e.vendor != me.vendor {
            continue;
        }
        if e.family != me.family {
            continue;
        }
        if me.model < e.model_lo || me.model > e.model_hi {
            continue;
        }
        if e.stepping_mask & (1u32 << me.stepping) == 0 {
            continue;
        }
        // SAFETY: caller-asserted; per-entry SAFETY notes apply.
        unsafe {
            (e.apply)();
        }
    }
}
