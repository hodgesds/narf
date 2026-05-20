//! AMD `amd-pstate` driver — Zen2 (Family 0x17, Model 0x30..=0xAF)
//! bring-up + CPPC programming.
//!
//! Sibling of `narf_power::pstate` (Intel HWP / SpeedStep + AMD
//! legacy P-states). Where `power::pstate` covers the older AMD
//! HwPstate MSRs (`MSR_AMD_PSTATE_DEF_0..7`) and Intel HWP,
//! `amd_pstate` here drives the modern Collaborative Processor
//! Performance Control (CPPC) interface that Zen2-and-later parts
//! expose. The two are deliberately parallel — `bare_main` picks
//! one or the other by CPUID vendor + family, never both.
//!
//! ## MSR map
//!
//! All four MSRs are in the AMD "shared" range and live on every
//! Zen2+ core. Addresses below match `arch/x86/include/asm/msr-index.h`
//! in the Linux kernel tree (NARF is GPL-2.0-or-later as of 2026-05-20):
//!
//! ```text
//!   0xC001_02B0   MSR_AMD_CPPC_CAP1     read-only — performance bounds
//!   0xC001_02B1   MSR_AMD_CPPC_REQ      read/write — request register
//!   0xC001_02B2   MSR_AMD_CPPC_CAP2     read-only — guaranteed perf
//!   0xC001_02B3   MSR_AMD_CPPC_STATUS   read-only — currently delivered
//! ```
//!
//! The CPPC enable bit is in the "passive-mode" `MSR_AMD_CPPC_ENABLE`
//! at `0xC001_0295` — `narf_power::cppc` owns that path. This module
//! is the "active-mode" amd-pstate driver: it assumes CPPC was
//! enabled elsewhere (or via firmware) and programs the request
//! register directly.
//!
//! ## References
//!
//! - Linux `drivers/cpufreq/amd-pstate.c` (canonical reference;
//!   `amd_pstate_update`, `amd_get_highest_perf`, `amd_pstate_epp_update`).
//! - Linux `arch/x86/kernel/cpu/amd.c` (Zen2 family/model detection
//!   patterns, `init_amd_zn` and `init_spectral_chicken`).
//! - Linux `arch/x86/include/asm/msr-index.h` (`MSR_AMD_CPPC_*`).
//! - AMD64 Architecture Programmer's Manual Vol 2 §17 "System Management Unit".
//! - AMD Renoir PPR (Processor Programming Reference) §1.5 "MSRs".
//!
//! ## Hardware target
//!
//! Zen2 mobile: Renoir / Lucienne / Matisse APUs — AMD Family 0x17,
//! Models 0x30..=0xAF. The detection helper [`is_zen2`] gates every
//! MSR access in this module on a positive CPUID match so the same
//! kernel image is safe to boot on non-AMD / non-Zen2 silicon (the
//! MSRs above are reserved on Intel and `#GP` on read).

#![cfg(target_arch = "x86_64")]
#![allow(dead_code)]

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::{rdmsr_or_gp, wrmsr_or_gp, MsrFault};

// ── MSR map ────────────────────────────────────────────────────────

/// CPPC capability register #1 — performance bounds.
///
/// Layout (AMD PPR Renoir §1.5; matches Linux's `struct amd_cpudata`
/// fields populated in `amd_get_highest_perf` /
/// `amd_get_lowest_perf`):
///
/// ```text
///   bits[7:0]    highest_perf            (peak boost)
///   bits[15:8]   nominal_perf            (long-term guaranteed)
///   bits[23:16]  lowest_nonlinear_perf   (knee of power curve)
///   bits[31:24]  lowest_perf             (slowest stable)
/// ```
pub const MSR_AMD_CPPC_CAP1: u32 = 0xC001_02B0;

/// CPPC request register — written to ask the firmware for a new
/// `(min, max, desired, epp)` operating tuple.
///
/// Layout (Linux `amd-pstate.c` `amd_pstate_update_perf`):
///
/// ```text
///   bits[7:0]    min_perf
///   bits[15:8]   max_perf
///   bits[23:16]  des_perf  (desired, 0 = autonomous)
///   bits[31:24]  epp       (energy-performance preference)
/// ```
pub const MSR_AMD_CPPC_REQ: u32 = 0xC001_02B1;

/// CPPC capability register #2 — guaranteed performance (mirrors
/// what `_CPC` would report under ACPI passive mode). Read-only.
pub const MSR_AMD_CPPC_CAP2: u32 = 0xC001_02B2;

/// CPPC status register — bits[7:0] hold the currently-delivered
/// performance value. Sampled live from the firmware governor.
pub const MSR_AMD_CPPC_STATUS: u32 = 0xC001_02B3;

/// Package thermal status MSR — bits[22:16] hold the digital
/// temperature reading (degrees below Tjmax). Architectural on AMD
/// and Intel both; we use it for the thermal hook.
///
/// Reference: Linux `arch/x86/include/asm/msr-index.h`
/// `MSR_IA32_PACKAGE_THERM_STATUS`.
pub const MSR_PKG_THERM_STATUS: u32 = 0x0000_01B1;

// ── EPP anchors ────────────────────────────────────────────────────

/// Canonical EPP anchor values (Linux `include/linux/cpufreq.h`,
/// `EPP_*`). AMD honours any byte 0..=255; these are the well-known
/// stops the userspace governor speaks.
pub mod epp {
    pub const PERFORMANCE: u8 = 0x00;
    pub const BALANCE_PERFORMANCE: u8 = 0x40;
    pub const BALANCE_POWER: u8 = 0x80;
    pub const POWER: u8 = 0xFF;
}

// ── Detection ──────────────────────────────────────────────────────

/// `AuthenticAMD` vendor string check via CPUID(0).
fn vendor_amd() -> bool {
    // SAFETY: leaf 0 is always defined.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    // "Auth" "enti" "cAMD"
    ebx == 0x6874_7541 && edx == 0x6974_6E65 && ecx == 0x444D_4163
}

/// Decoded display family/model per the AMD64 APM "Family-Model-
/// Stepping decode": extended-family adds to base-family when
/// base-family == 0xF; extended-model is shifted in when family >=
/// 0xF (which always holds for modern AMD). Mirrors Linux's
/// `early_identify_cpu` / `get_cpu_address_sizes`.
fn family_model() -> (u16, u16) {
    // SAFETY: leaf 1 always defined.
    let (sig, _, _, _) = unsafe { cpuid(1, 0) };
    let base_family = ((sig >> 8) & 0xF) as u16;
    let ext_family = ((sig >> 20) & 0xFF) as u16;
    let base_model = ((sig >> 4) & 0xF) as u16;
    let ext_model = ((sig >> 16) & 0xF) as u16;
    let family = base_family + if base_family == 0xF { ext_family } else { 0 };
    // AMD modern silicon always reports base_family == 0xF, so the
    // ext_model is in play. Linux `arch/x86/kernel/cpu/amd.c` uses the
    // same condition.
    let model = if base_family >= 0x6 || base_family == 0xF {
        base_model | (ext_model << 4)
    } else {
        base_model
    };
    (family, model)
}

/// True iff this CPU is AMD Family 0x17 (Zen / Zen+ / Zen2), Model
/// 0x30..=0xAF — the Zen2-Renoir / Lucienne / Matisse silicon
/// range. Outside this range the driver bails so we don't poke
/// MSRs whose layout we haven't verified against a public PPR.
///
/// Linux makes the same family/model cut in `init_amd_zn` /
/// `init_amd` (`arch/x86/kernel/cpu/amd.c`).
pub fn is_zen2() -> bool {
    if !vendor_amd() {
        return false;
    }
    let (family, model) = family_model();
    family == 0x17 && (0x30..=0xAF).contains(&model)
}

// ── CAP1 / STATUS decoders ────────────────────────────────────────

/// Decoded `MSR_AMD_CPPC_CAP1` value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CppcCaps {
    pub highest_perf: u8,
    pub nominal_perf: u8,
    pub lowest_nonlinear_perf: u8,
    pub lowest_perf: u8,
}

impl CppcCaps {
    /// Raw decode from the MSR value. Layout per Linux
    /// `drivers/cpufreq/amd-pstate.c::amd_pstate_init_perf` and
    /// AMD Renoir PPR §1.5.
    pub const fn from_raw(v: u64) -> Self {
        Self {
            highest_perf: (v & 0xFF) as u8,
            nominal_perf: ((v >> 8) & 0xFF) as u8,
            lowest_nonlinear_perf: ((v >> 16) & 0xFF) as u8,
            lowest_perf: ((v >> 24) & 0xFF) as u8,
        }
    }
}

/// Read [`MSR_AMD_CPPC_CAP1`]. Uses the GP-safe variant so a
/// BIOS-locked MSR surfaces as `Err` instead of wedging boot.
/// Returns `None` when CPU is not Zen2.
pub fn read_caps() -> Option<Result<CppcCaps, MsrFault>> {
    if !is_zen2() {
        return None;
    }
    Some(rdmsr_or_gp(MSR_AMD_CPPC_CAP1).map(CppcCaps::from_raw))
}

/// Read [`MSR_AMD_CPPC_STATUS`]. Bits[7:0] hold the currently
/// delivered performance value (live, fed back by the firmware
/// governor — Linux samples this in `amd_pstate_sample`).
pub fn read_status() -> Option<Result<u8, MsrFault>> {
    if !is_zen2() {
        return None;
    }
    Some(rdmsr_or_gp(MSR_AMD_CPPC_STATUS).map(|v| (v & 0xFF) as u8))
}

// ── Request register ──────────────────────────────────────────────

/// Build the 64-bit value to write to [`MSR_AMD_CPPC_REQ`] from
/// the four field bytes. Mirrors Linux's
/// `amd_pstate_update_perf` packing.
#[inline]
pub const fn build_request(min_perf: u8, max_perf: u8, des_perf: u8, epp: u8) -> u64 {
    (min_perf as u64)
        | ((max_perf as u64) << 8)
        | ((des_perf as u64) << 16)
        | ((epp as u64) << 24)
}

/// Decode a 64-bit `MSR_AMD_CPPC_REQ` value back into its four
/// fields. Inverse of [`build_request`] — exposed for diagnostics
/// + the smoke tests.
#[inline]
pub const fn decode_request(v: u64) -> (u8, u8, u8, u8) {
    (
        (v & 0xFF) as u8,
        ((v >> 8) & 0xFF) as u8,
        ((v >> 16) & 0xFF) as u8,
        ((v >> 24) & 0xFF) as u8,
    )
}

/// Issue an amd-pstate request: write [`MSR_AMD_CPPC_REQ`] with the
/// packed `(min, max, desired, epp)` tuple. Returns `None` on
/// non-Zen2 CPUs (no MSR to write); the inner `Result` distinguishes
/// a clean write from a `#GP` (BIOS lock).
///
/// Reference: Linux `drivers/cpufreq/amd-pstate.c`,
/// `amd_pstate_update_perf` — same field packing, same EPP byte in
/// the high lane.
pub fn amd_pstate_request(
    min_perf: u8,
    max_perf: u8,
    des_perf: u8,
    epp: u8,
) -> Option<Result<(), MsrFault>> {
    if !is_zen2() {
        return None;
    }
    let v = build_request(min_perf, max_perf, des_perf, epp);
    Some(wrmsr_or_gp(MSR_AMD_CPPC_REQ, v))
}

// ── Thermal hook ──────────────────────────────────────────────────

/// Read the package thermal-status MSR. Bits[22:16] = digital
/// readout (degrees below `Tjmax`); bit[31] = thermal trip.
///
/// Returns `None` if the read `#GP`'d (some Family 0x17 OEM BIOSes
/// lock the package MSR). Caller pairs this with the SMU thermal
/// MMIO at D0F3 BAR + 0x59800 for a redundant reading — the SMU
/// MMIO surface lives in `drivers/platform`, this module only
/// exposes the MSR-side reading.
///
/// Reference: AMD64 APM Vol 2 §17.6 + Linux
/// `drivers/hwmon/k10temp.c` (Tctl/Tdie decoding helpers).
pub fn read_pkg_therm_status() -> Result<u64, MsrFault> {
    rdmsr_or_gp(MSR_PKG_THERM_STATUS)
}

// ── Boot bring-up ─────────────────────────────────────────────────

/// Outcome of [`boot_init`]. Surfaced to `bare_main` so the boot
/// log can show what happened in one line.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BootInitOutcome {
    /// CPU isn't an AMD Family 0x17 / Model 0x30..=0xAF part.
    NotZen2,
    /// Reading `MSR_AMD_CPPC_CAP1` `#GP`'d — BIOS likely has CPPC
    /// MSRs locked. We didn't write anything.
    Cap1Gp,
    /// Reading CAP1 succeeded but `MSR_AMD_CPPC_REQ` `#GP`'d on
    /// write — BIOS locked the write path. Hardware stays at the
    /// firmware-chosen operating point.
    ReqGp,
    /// Programmed `MSR_AMD_CPPC_REQ` to `(lowest_nonlinear,
    /// highest, nominal, BALANCE_PERFORMANCE)` so the firmware
    /// governor targets nominal and is allowed to boost to highest
    /// under load, but won't pin at peak forever on a laptop.
    Programmed {
        caps: CppcCaps,
        des_perf: u8,
        epp: u8,
    },
}

/// Boot-time amd-pstate bring-up. On a matching Zen2 CPU, reads
/// `MSR_AMD_CPPC_CAP1` and programs `MSR_AMD_CPPC_REQ` to target
/// nominal performance — so the laptop doesn't boost-pin at peak
/// forever after firmware hands off.
///
/// Field choice (matches Linux's amd-pstate default policy in
/// `amd_pstate_set_epp` / `amd_pstate_init_perf`):
///
///   * `min_perf` = `lowest_nonlinear_perf` — the firmware can drop
///     below nominal under low load, but not into the inefficient
///     deep-idle region.
///   * `max_perf` = `highest_perf` — boost is allowed; the EPP
///     decides how aggressively it's taken.
///   * `des_perf` = `nominal_perf` — long-term target; with EPP
///     balanced the governor sits here under typical load.
///   * `epp` = `BALANCE_PERFORMANCE` — anchor 0x40.
///
/// No `unsafe` because the MSR accesses use the probe-armed
/// variants; a firmware lock surfaces as `Cap1Gp` / `ReqGp` rather
/// than wedging boot.
pub fn boot_init() -> BootInitOutcome {
    if !is_zen2() {
        return BootInitOutcome::NotZen2;
    }
    let caps = match rdmsr_or_gp(MSR_AMD_CPPC_CAP1) {
        Ok(v) => CppcCaps::from_raw(v),
        Err(_) => return BootInitOutcome::Cap1Gp,
    };
    let min = caps.lowest_nonlinear_perf;
    let max = caps.highest_perf;
    let des = caps.nominal_perf;
    let epp = epp::BALANCE_PERFORMANCE;
    let v = build_request(min, max, des, epp);
    if wrmsr_or_gp(MSR_AMD_CPPC_REQ, v).is_err() {
        return BootInitOutcome::ReqGp;
    }
    BootInitOutcome::Programmed {
        caps,
        des_perf: des,
        epp,
    }
}
