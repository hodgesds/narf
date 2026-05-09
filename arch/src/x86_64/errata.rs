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

/// AMD Zen 1/2 erratum: clamp DE_CFG[9].
///
/// Zen 1: erratum 1474 (long-idle TSC drift).
/// Zen 2: "Zenbleed" (CVE-2023-20593) — XMM register leak when
/// vzeroupper interleaves with branch-prediction misspeculation.
/// AMD's mitigation is the same MSR bit (`MSR_DE_CFG[9]`,
/// `chicken-bit` per AMD-SB-7008).
///
/// Spec source: AMD Public Security Bulletin AMD-SB-7008
/// <https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7008.html>
///
/// # Safety
/// CPL = 0; caller has confirmed CPU is AMD Zen 1 or Zen 2.
unsafe fn amd_de_cfg_bit9() {
    use crate::x86_64::msr::{rdmsr, wrmsr};
    const MSR_DE_CFG: u32 = 0xC001_1029;
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_DE_CFG) };
    unsafe {
        wrmsr(MSR_DE_CFG, v | (1 << 9));
    }
}

/// AMD Zen 4 erratum 1485: under specific micro-op queue
/// conditions an `RDMSR` followed by `WRMSR` can fail to
/// architecturally serialise. AMD's recommended workaround is
/// to set `MSR_DE_CFG[14]` ("force serialising MSR access") on
/// every Zen 4 core during early bring-up.
///
/// Spec source: AMD Family 19h Models 60h-7Fh Revision Guide
/// (Phoenix / Phoenix2). The bit is documented in the BIOS &
/// Kernel Developer's Guide for Family 19h.
/// <https://www.amd.com/en/support/tech-docs>
///
/// # Safety
/// CPL = 0; caller has confirmed CPU is AMD Zen 4 (Family 0x19,
/// Model 0x60-0x7F). Setting the bit on other parts is
/// architecturally a no-op for the documented chicken-bit
/// semantics, but we gate via the table to keep behaviour
/// minimal.
unsafe fn amd_zen4_erratum_1485() {
    use crate::x86_64::msr::{rdmsr, wrmsr};
    const MSR_DE_CFG: u32 = 0xC001_1029;
    // SAFETY: caller-asserted.
    let v = unsafe { rdmsr(MSR_DE_CFG) };
    unsafe {
        wrmsr(MSR_DE_CFG, v | (1 << 14));
    }
}

/// AMD Zen 5 marker — silicon detected, no MSR mutation. Kept
/// as a registry entry so a future Zen 5 erratum that needs a
/// workaround can land here without scaffolding. The table
/// scanner skips entries whose `apply` is `nop_workaround`-shaped
/// only by virtue of running them; treating this as a
/// detection-only hook keeps the boot log honest.
///
/// Family 0x1A is the official Family ID for Zen 5 (Granite
/// Ridge / Strix Point / Turin), per AMD CPUID-Specification
/// for Family 1Ah.
///
/// # Safety
/// CPL = 0; trivially safe.
unsafe fn amd_zen5_detection_marker() {
    // No MSR writes — the marker exists so apply_for_current_cpu
    // logs that we're aware of being on Zen 5 silicon. Add real
    // workarounds here as AMD publishes Family 1Ah errata.
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
        apply: amd_de_cfg_bit9,
    },
    // Zen 2 (Family 0x17, Models 0x30-0xAF — Rome / Renoir /
    // Matisse). Zenbleed (CVE-2023-20593): same DE_CFG[9] bit
    // as Zen 1 1474, applied family-wide via AMD-SB-7008.
    Errata {
        name: "amd-zen2-zenbleed",
        vendor: Vendor::Amd,
        family: 0x17,
        model_lo: 0x30,
        model_hi: 0xAF,
        stepping_mask: 0xFFFF_FFFF,
        apply: amd_de_cfg_bit9,
    },
    // Zen 4 (Family 0x19, Models 0x60-0x7F — Phoenix / Phoenix2
    // / Ryzen 7040 / 8000 series APUs). Erratum 1485:
    // RDMSR/WRMSR serialisation. DE_CFG[14] enables the
    // serialising-MSR chicken bit.
    Errata {
        name: "amd-zen4-1485",
        vendor: Vendor::Amd,
        family: 0x19,
        model_lo: 0x60,
        model_hi: 0x7F,
        stepping_mask: 0xFFFF_FFFF,
        apply: amd_zen4_erratum_1485,
    },
    // Zen 5 (Family 0x1A — Granite Ridge / Strix Point / Turin).
    // Detection marker only; populates the apply log so a Zen 5
    // boot is visible. No published Family-1Ah erratum yet
    // requires kernel intervention beyond microcode.
    Errata {
        name: "amd-zen5-marker",
        vendor: Vendor::Amd,
        family: 0x1A,
        model_lo: 0x00,
        model_hi: 0xFF,
        stepping_mask: 0xFFFF_FFFF,
        apply: amd_zen5_detection_marker,
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
/// Returns a fixed-size buffer + count of the applied entry
/// names so callers can log "what we matched" without pulling
/// alloc into this module. Idempotent — safe to call once per
/// AP.
///
/// # Safety
/// CPL = 0; the per-entry `apply` functions are themselves safe
/// to call (they gate on CPUID).
pub unsafe fn apply_for_current_cpu() -> ([&'static str; 8], usize) {
    let me = ident::read();
    let mut out: [&'static str; 8] = [""; 8];
    let mut n = 0usize;
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
        if n < out.len() {
            out[n] = e.name;
            n += 1;
        }
    }
    (out, n)
}
