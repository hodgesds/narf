//! Intel HWP (Hardware P-states) — Stage-0 summary + activation.
//!
//! HWP is Intel's dominant CPU frequency scaling interface from
//! Skylake (6th gen) onward. The hardware autonomously selects a
//! P-state inside the window the OS supplies via `IA32_HWP_REQUEST`,
//! constrained by the platform's `IA32_HWP_CAPABILITIES` (highest /
//! guaranteed / efficient / lowest performance, on a unitless 0..255
//! scale).
//!
//! Stage-0 scope:
//!   1. Vendor-gate on `GenuineIntel`.
//!   2. CPUID 0x06 EAX[7] → HWP supported?
//!   3. Read `IA32_HWP_CAPABILITIES` via `rdmsr_or_gp` (BIOS may
//!      lock the read on some OEMs).
//!   4. Decode the four perf values + an approximate MHz figure via
//!      the Intel base-frequency helpers in `arch::x86_64::tsc`
//!      (CPUID 0x16 / `MSR_PLATFORM_INFO`).
//!   5. Log a one-line summary.
//!   6. Set a sane initial `IA32_HWP_REQUEST` (min=lowest,
//!      max=highest, desired=0/autonomous, EPP=0x80 balanced).
//!
//! Sticky bit: `IA32_PM_ENABLE` bit 0 cannot be cleared without a
//! CPU reset, so the activation is one-shot per boot. Idempotent on
//! re-entry.
//!
//! Stage-0 deliberately stops here. A real cpufreq policy/governor
//! framework (per-CPU request, EPP knob, telemetry on
//! `IA32_HWP_STATUS` excursions) is a larger Stage-1+ project.
//!
//! Spec references:
//! - Intel SDM Vol 4 §2.16 (Performance Monitoring / Power
//!   Management MSRs) — `IA32_PM_ENABLE`, `IA32_HWP_CAPABILITIES`,
//!   `IA32_HWP_REQUEST`, `IA32_HWP_STATUS`.
//! - Intel SDM Vol 3B §14.4 (Hardware-Controlled Performance
//!   States).
//! - Linux `drivers/cpufreq/intel_pstate.c` — same activation order
//!   (caps read → request program → enable sticky) is documented in
//!   `intel_pstate_hwp_enable` / `intel_pstate_get_hwp_cap`.

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

extern crate alloc;

use core::fmt::Write as _;

use narf_arch::x86_64::cpuid::cpuid;
use narf_arch::x86_64::msr::{rdmsr_or_gp, wrmsr_or_gp};

use crate::pstate::{
    MSR_IA32_HWP_CAPABILITIES, MSR_IA32_HWP_REQUEST, MSR_IA32_PM_ENABLE,
};

/// EPP byte values per Intel SDM Vol 4 §2.16. The hardware
/// interprets the byte as a hint to the autonomous selector;
/// `0x80` is the conventional "balanced" midpoint Linux uses as
/// its default for the `intel_pstate` driver's "powersave"
/// governor (which is in fact balanced — confusingly named).
pub const EPP_PERFORMANCE: u8 = 0x00;
pub const EPP_BALANCED_PERFORMANCE: u8 = 0x80;
pub const EPP_POWERSAVE: u8 = 0xFF;

/// Decoded `IA32_HWP_CAPABILITIES` (Intel SDM Vol 4 §2.16):
/// ```text
///   bits[7:0]   highest_perf
///   bits[15:8]  guaranteed_perf
///   bits[23:16] most_efficient_perf
///   bits[31:24] lowest_perf
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HwpCapabilities {
    pub highest_perf: u8,
    pub guaranteed_perf: u8,
    pub efficient_perf: u8,
    pub lowest_perf: u8,
}

impl HwpCapabilities {
    pub fn decode(raw: u64) -> Self {
        HwpCapabilities {
            highest_perf: (raw & 0xFF) as u8,
            guaranteed_perf: ((raw >> 8) & 0xFF) as u8,
            efficient_perf: ((raw >> 16) & 0xFF) as u8,
            lowest_perf: ((raw >> 24) & 0xFF) as u8,
        }
    }
}

/// CPUID 0x06 EAX feature bits — the "Thermal and Power Management"
/// leaf documented in Intel SDM Vol 2A §3.2.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct HwpFeatures {
    /// EAX[7]  HWP_BASE — `IA32_PM_ENABLE` + `IA32_HWP_*` present.
    pub hwp: bool,
    /// EAX[8]  HWP_NOTIFICATION — `IA32_HWP_INTERRUPT` present.
    pub notification: bool,
    /// EAX[9]  HWP_ACTIVITY_WINDOW — bits[41:32] of REQUEST live.
    pub activity_window: bool,
    /// EAX[10] HWP_EPP — Energy Performance Preference (bits[31:24]
    /// of `IA32_HWP_REQUEST`).
    pub epp: bool,
    /// EAX[11] HWP_PLR — Package-Level Request MSR present.
    pub package_level_request: bool,
    /// EAX[20] HWP fast-write (low-latency `wrmsr` to REQUEST).
    pub fast_write: bool,
}

impl HwpFeatures {
    /// Probe CPUID 0x06 EAX feature bits. Returns the all-`false`
    /// shape on CPUs that don't expose the leaf at all (AMD: leaf
    /// reports 0; Intel pre-Nehalem: leaf absent).
    pub fn probe() -> Self {
        // SAFETY: leaf 0 is always defined on x86_64.
        let (max, _, _, _) = unsafe { cpuid(0, 0) };
        if max < 6 {
            return HwpFeatures::default();
        }
        // SAFETY: leaf 6 defined when max >= 6.
        let (eax, _, _, _) = unsafe { cpuid(6, 0) };
        HwpFeatures {
            hwp: eax & (1 << 7) != 0,
            notification: eax & (1 << 8) != 0,
            activity_window: eax & (1 << 9) != 0,
            epp: eax & (1 << 10) != 0,
            package_level_request: eax & (1 << 11) != 0,
            fast_write: eax & (1 << 20) != 0,
        }
    }
}

/// Vendor check — `GenuineIntel`. Mirrors `pstate::vendor_intel()`
/// rather than depending on it because keeping the HWP module
/// self-contained makes the vendor gate trivially auditable.
fn vendor_intel() -> bool {
    // SAFETY: leaf 0 is always defined.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    // "Genu" "ineI" "ntel"
    ebx == 0x756E_6547 && edx == 0x4965_6E69 && ecx == 0x6C65_746E
}

/// Outcome of [`intel_hwp_summary`]. Lets a caller / test
/// distinguish "vendor mismatch" from "no HWP" from "BIOS locked
/// the caps MSR" from "we successfully programmed it" without
/// re-reading the log line.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HwpSummary {
    /// CPU vendor isn't `GenuineIntel`. No-op.
    NotIntel,
    /// Intel CPU but CPUID 0x06 EAX[7] = 0. No HWP MSRs.
    NotSupported,
    /// HWP advertised; `IA32_HWP_CAPABILITIES` read `#GP`'d
    /// (BIOS-locked / virtualised hypervisor). Stays at firmware
    /// default.
    CapabilitiesGp,
    /// HWP advertised + caps read; `IA32_PM_ENABLE` write `#GP`'d.
    /// The enable bit is sticky so subsequent attempts also fail.
    EnableGp,
    /// Enable succeeded; `IA32_HWP_REQUEST` write `#GP`'d. The
    /// hardware will run with whatever firmware seeded into the MSR
    /// at boot (often `lowest..highest, EPP=balanced` already).
    RequestGp,
    /// Full happy path: caps read, enabled, request programmed.
    Programmed(HwpCapabilities),
}

/// Approximate per-unit MHz given the platform's base frequency and
/// the `guaranteed_perf` value: HWP performance units are unitless
/// 0..255 with the guaranteed value calibrated to the base
/// frequency reported by CPUID 0x16 (or `MSR_PLATFORM_INFO`
/// max-non-turbo ratio × 100 MHz BCLK). Linux uses the same scale
/// factor in `intel_pstate_get_hwp_cap`.
///
/// Returns `None` if neither base-frequency source is available
/// (virtualised hosts that don't populate CPUID 0x16 and don't
/// expose MSR 0xCE — rare) or if `guaranteed_perf` is zero
/// (a malformed CAPABILITIES read, e.g. all-ones from a borked
/// hypervisor).
fn perf_to_mhz(perf: u8, guaranteed_perf: u8) -> Option<u32> {
    if guaranteed_perf == 0 {
        return None;
    }
    let base_hz = base_frequency_hz()?;
    let base_mhz = (base_hz / 1_000_000) as u32;
    Some((perf as u32).saturating_mul(base_mhz) / guaranteed_perf as u32)
}

/// Base (non-turbo) frequency in Hz. Tries CPUID 0x16 EAX first
/// (the architectural answer); falls back to `MSR_PLATFORM_INFO`
/// bits[15:8] × 100 MHz BCLK on Sandy Bridge+ Intel where the
/// CPUID leaf reports zero (some hypervisors).
fn base_frequency_hz() -> Option<u64> {
    if let Some(hz) = narf_arch::x86_64::tsc::__from_cpuid_16h() {
        return Some(hz);
    }
    narf_arch::x86_64::tsc::__from_msr_platform_info()
}

/// Stage-0 summary + activation. Vendor-gates inside; safe to call
/// from a vendor-agnostic initcall alongside the AMD summary —
/// only one will produce log output. Idempotent across calls
/// (`IA32_PM_ENABLE` is sticky; `IA32_HWP_REQUEST` accepts the
/// same value repeatedly).
///
/// Logs one of these shapes to `narf_console`:
/// ```text
///   hwp: not supported                                        // non-Intel or CPUID 0x06 EAX[7] = 0
///   hwp: capabilities #GP — firmware default                  // BIOS-locked CAPABILITIES read
///   hwp: highest=NN (M MHz), guaranteed=NN (M MHz), ...       // happy path
/// ```
pub fn intel_hwp_summary() -> HwpSummary {
    if !vendor_intel() {
        // Silent vendor gate — AMD parts boot through this same
        // initcall and `amd_pstate_summary` / CPPC handle them
        // separately. Logging an Intel-flavoured "n/a" on AMD would
        // be misleading.
        return HwpSummary::NotIntel;
    }
    let feats = HwpFeatures::probe();
    if !feats.hwp {
        let _ = writeln!(narf_console::Writer, "  hwp: not supported");
        return HwpSummary::NotSupported;
    }

    let caps_raw = match rdmsr_or_gp(MSR_IA32_HWP_CAPABILITIES) {
        Ok(v) => v,
        Err(_) => {
            let _ = writeln!(
                narf_console::Writer,
                "  hwp: capabilities #GP — firmware default"
            );
            return HwpSummary::CapabilitiesGp;
        }
    };
    let caps = HwpCapabilities::decode(caps_raw);

    // Log the four perf values + approximate MHz figures.
    let highest_mhz = perf_to_mhz(caps.highest_perf, caps.guaranteed_perf);
    let guaranteed_mhz = perf_to_mhz(caps.guaranteed_perf, caps.guaranteed_perf);
    let efficient_mhz = perf_to_mhz(caps.efficient_perf, caps.guaranteed_perf);
    let lowest_mhz = perf_to_mhz(caps.lowest_perf, caps.guaranteed_perf);

    let mut line = alloc::string::String::new();
    let _ = write!(&mut line, "  hwp: ");
    let _ = write!(&mut line, "highest={}", caps.highest_perf);
    if let Some(m) = highest_mhz {
        let _ = write!(&mut line, " ({} MHz)", m);
    }
    let _ = write!(&mut line, ", guaranteed={}", caps.guaranteed_perf);
    if let Some(m) = guaranteed_mhz {
        let _ = write!(&mut line, " ({} MHz)", m);
    }
    let _ = write!(&mut line, ", efficient={}", caps.efficient_perf);
    if let Some(m) = efficient_mhz {
        let _ = write!(&mut line, " ({} MHz)", m);
    }
    let _ = write!(&mut line, ", lowest={}", caps.lowest_perf);
    if let Some(m) = lowest_mhz {
        let _ = write!(&mut line, " ({} MHz)", m);
    }
    let _ = write!(
        &mut line,
        ", EPP_supported={}",
        if feats.epp { 'Y' } else { 'N' }
    );
    let _ = writeln!(narf_console::Writer, "{}", line);

    // Activation: write `IA32_PM_ENABLE` bit 0 (sticky), then
    // program `IA32_HWP_REQUEST` with (min=lowest, max=highest,
    // desired=0=autonomous, EPP=0x80=balanced).
    if wrmsr_or_gp(MSR_IA32_PM_ENABLE, 1).is_err() {
        let _ = writeln!(
            narf_console::Writer,
            "  hwp: enable #GP — firmware default"
        );
        return HwpSummary::EnableGp;
    }
    let req = (caps.lowest_perf as u64)
        | ((caps.highest_perf as u64) << 8)
        | (0u64 << 16)
        | ((EPP_BALANCED_PERFORMANCE as u64) << 24);
    if wrmsr_or_gp(MSR_IA32_HWP_REQUEST, req).is_err() {
        let _ = writeln!(
            narf_console::Writer,
            "  hwp: request #GP — firmware default"
        );
        return HwpSummary::RequestGp;
    }
    HwpSummary::Programmed(caps)
}
