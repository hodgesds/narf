//! AMD DPM (Dynamic Power Management) — P-state transitions
//! driven by display + GFX + video workload signals.
//!
//! DPM sits above the SMU's mailbox protocol and chooses
//! per-domain (GFX / FCLK / SOCCLK / UCLK / VCLK / DCLK) clock
//! levels per workload. The SMU exposes discrete DPM levels
//! (0 = lowest power, N = highest performance); the host's job
//! is to nudge the SMU toward the right level based on what's
//! happening:
//!
//! - **Display load** — active CRTC count + refresh rate.
//!   2+ displays at 4K60 needs FCLK boosted; 1 display at 60 Hz
//!   stays in mid-tier.
//! - **GFX load** — busy% on the CP. Trailing 100 ms average.
//! - **Video load** — VCN decode/encode active.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/amd/pm/amdgpu_dpm.c` — top-level DPM
//!   coordinator
//! - Linux `drivers/gpu/drm/amd/pm/swsmu/smu13/smu_v13_0.c`
//!   (`smu_v13_0_set_performance_level`) — Phoenix-class SMU
//! - Linux `drivers/gpu/drm/amd/pm/swsmu/smu12/smu_v12_0.c`
//!   (`smu_v12_0_set_default_dpm_tables`) — Renoir-class
//! - Linux `drivers/gpu/drm/amd/include/amdgpu_smu.h` — power
//!   levels + workload-mask flags
//!
//! GPL-2.0-or-later (matches NARF). Adapted directly.
//!
//! ## Performance levels
//!
//! Linux's `amd_dpm_forced_level` exposes:
//!   - AUTO       — let SMU pick
//!   - LOW        — pin to lowest DPM
//!   - HIGH       — pin to highest DPM
//!   - MANUAL     — host picks per-domain
//!   - PROFILE_*  — workload profiles (video, compute, etc.)
//!
//! This module ports the AUTO + workload-mask path, plus a
//! reduced MANUAL surface for diagnostics.

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu_smu::ClockDomain;

// ── Performance level ────────────────────────────────────────────

/// Forced performance level. Mirrors Linux's
/// `amd_dpm_forced_level`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum PerfLevel {
    /// SMU decides per real-time telemetry. Default at boot.
    #[default]
    Auto,
    /// Pin to lowest DPM (battery save).
    Low,
    /// Pin to highest DPM (benchmark mode).
    High,
    /// Host-driven per-domain. Use `Dpm::set_domain` to drive.
    Manual,
    /// Pinned at standard-fan-curve power profile.
    Standard,
    /// 3D mode — game workload.
    Game3d,
    /// Pin at video-decode profile.
    VideoEncode,
    /// VR profile.
    Vr,
    /// Compute (OpenCL / Vulkan-Compute / HIP).
    Compute,
}

// ── Workload mask ────────────────────────────────────────────────

/// Workload-classification flags. The SMU picks DPM levels per
/// active workload via the WORKLOAD_PPLIB_MASK bitmap. Mirrors
/// Linux's `WORKLOAD_PPLIB_*_BIT` defines.
pub struct WorkloadBits;
impl WorkloadBits {
    pub const DEFAULT: u32 = 1 << 0;
    pub const FULLSCREEN_3D: u32 = 1 << 1;
    pub const POWER_SAVING: u32 = 1 << 2;
    pub const VIDEO: u32 = 1 << 3;
    pub const VR: u32 = 1 << 4;
    pub const COMPUTE: u32 = 1 << 5;
    pub const CUSTOM: u32 = 1 << 6;
}

impl core::fmt::Debug for WorkloadBits {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WorkloadBits")
    }
}

// ── Workload telemetry inputs ───────────────────────────────────

/// Inputs the host feeds to the DPM coordinator. Sampled from
/// the IH ring (vblank counters), GFX ring (last fence age),
/// and VCN status.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DpmInputs {
    /// Number of CRTCs currently scanning out.
    pub active_crtcs: u8,
    /// Aggregate refresh rate (sum over active CRTCs), Hz.
    pub aggregate_refresh_hz: u32,
    /// Trailing 100 ms GFX busy percentage (0..=100).
    pub gfx_busy_pct: u8,
    /// VCN decode busy?
    pub vcn_decode_busy: bool,
    /// VCN encode busy?
    pub vcn_encode_busy: bool,
    /// `true` if the system is on battery.
    pub on_battery: bool,
}

impl DpmInputs {
    /// Classify into a `WorkloadBits` mask. Multiple bits can
    /// set simultaneously (3D + Video for browser playback,
    /// Compute + VR for AR apps, etc.).
    pub fn workload_mask(&self) -> u32 {
        let mut mask = 0u32;
        if self.on_battery && self.gfx_busy_pct < 30 {
            mask |= WorkloadBits::POWER_SAVING;
        }
        if self.gfx_busy_pct >= 70 {
            mask |= WorkloadBits::FULLSCREEN_3D;
        }
        if self.vcn_decode_busy || self.vcn_encode_busy {
            mask |= WorkloadBits::VIDEO;
        }
        // Default flag always set so SMU has something to fall
        // back on.
        mask |= WorkloadBits::DEFAULT;
        mask
    }

    /// Recommended performance level given inputs.
    pub fn recommended_level(&self) -> PerfLevel {
        if self.on_battery && self.gfx_busy_pct < 15 && self.active_crtcs <= 1 {
            return PerfLevel::Low;
        }
        if self.gfx_busy_pct >= 80 {
            return PerfLevel::Game3d;
        }
        if self.vcn_decode_busy || self.vcn_encode_busy {
            return PerfLevel::VideoEncode;
        }
        PerfLevel::Auto
    }
}

// ── Domain DPM table ─────────────────────────────────────────────

/// DPM table for one clock domain. The SMU publishes this at
/// boot via `GetDpmFreqByIndex`; the host caches it so it can
/// pick a level without an SMU round-trip on every workload
/// transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DpmTable {
    pub domain: ClockDomain,
    /// Available levels (frequency MHz at each index).
    pub levels: Vec<u32>,
    /// Soft min (host's lower clamp).
    pub soft_min_level: u8,
    /// Soft max (host's upper clamp).
    pub soft_max_level: u8,
    /// Currently selected level.
    pub current_level: u8,
}

impl DpmTable {
    pub fn new(domain: ClockDomain, levels: Vec<u32>) -> Self {
        let max = levels.len().saturating_sub(1) as u8;
        Self {
            domain,
            levels,
            soft_min_level: 0,
            soft_max_level: max,
            current_level: 0,
        }
    }

    /// `true` if the table has at least one level.
    pub fn has_levels(&self) -> bool {
        !self.levels.is_empty()
    }

    pub fn level_count(&self) -> u8 {
        self.levels.len() as u8
    }

    /// Highest available frequency. 0 if empty table.
    pub fn highest_mhz(&self) -> u32 {
        self.levels.last().copied().unwrap_or(0)
    }

    /// Pin to a specific level (clamped to soft min/max).
    /// Returns the clamped level actually selected.
    pub fn pin(&mut self, level: u8) -> u8 {
        let clamped = level.clamp(self.soft_min_level, self.soft_max_level);
        self.current_level = clamped;
        clamped
    }

    /// Set soft constraints. `(min, max)` is clamped to the
    /// table's range; if min > max, swap.
    pub fn set_soft_range(&mut self, mut min: u8, mut max: u8) {
        let last = self.level_count().saturating_sub(1);
        if min > max {
            core::mem::swap(&mut min, &mut max);
        }
        self.soft_min_level = min.min(last);
        self.soft_max_level = max.min(last);
        // Re-clamp current.
        self.current_level = self
            .current_level
            .clamp(self.soft_min_level, self.soft_max_level);
    }
}

// ── DPM coordinator ──────────────────────────────────────────────

/// Top-level DPM state. One per AMD GPU. Owns per-domain DPM
/// tables + the current performance level.
#[derive(Clone, Debug, Default)]
pub struct Dpm {
    pub level: PerfLevel,
    pub tables: Vec<DpmTable>,
    /// Cached workload mask from last input.
    pub last_workload_mask: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DpmError {
    NoSuchDomain,
    EmptyTable,
}

impl Dpm {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a domain's DPM table (from SMU boot probe).
    pub fn register_table(&mut self, table: DpmTable) {
        // Replace if domain already present.
        if let Some(slot) = self.tables.iter_mut().find(|t| t.domain == table.domain) {
            *slot = table;
        } else {
            self.tables.push(table);
        }
    }

    /// Fetch domain's table (read-only).
    pub fn table(&self, domain: ClockDomain) -> Option<&DpmTable> {
        self.tables.iter().find(|t| t.domain == domain)
    }

    /// Pin a domain to a level (MANUAL mode). Returns the
    /// clamped level. Fails if the domain has no table or the
    /// table is empty.
    pub fn set_domain(&mut self, domain: ClockDomain, level: u8) -> Result<u8, DpmError> {
        let tbl = self
            .tables
            .iter_mut()
            .find(|t| t.domain == domain)
            .ok_or(DpmError::NoSuchDomain)?;
        if !tbl.has_levels() {
            return Err(DpmError::EmptyTable);
        }
        Ok(tbl.pin(level))
    }

    /// Apply inputs: classify workload, update level, and
    /// produce a list of `(domain, target_level)` the caller
    /// pushes through the SMU mailbox.
    ///
    /// The mapping is intentionally simple:
    ///   - Low    → pin everything to 0
    ///   - High   → pin everything to max
    ///   - Auto   → mid (level/2)
    ///   - VideoEncode → VCLK/DCLK at max, GFX low
    ///   - Game3d → GFX/UCLK at max
    pub fn apply_inputs(&mut self, inputs: DpmInputs) -> Vec<(ClockDomain, u8)> {
        self.last_workload_mask = inputs.workload_mask();
        let recommended = inputs.recommended_level();
        if self.level == PerfLevel::Auto {
            // Allow `Auto` to drift toward the recommendation.
            self.level = recommended;
        }
        let mut targets = Vec::with_capacity(self.tables.len());
        for tbl in &mut self.tables {
            let max = tbl.level_count().saturating_sub(1);
            let target = match (self.level, tbl.domain) {
                (PerfLevel::Low, _) => 0,
                (PerfLevel::High, _) => max,
                (PerfLevel::Game3d, ClockDomain::Gfxclk) => max,
                (PerfLevel::Game3d, ClockDomain::Uclk) => max,
                (PerfLevel::Game3d, _) => mid(max),
                (PerfLevel::VideoEncode, ClockDomain::Vclk) => max,
                (PerfLevel::VideoEncode, ClockDomain::Dclk) => max,
                (PerfLevel::VideoEncode, ClockDomain::Gfxclk) => 0,
                (PerfLevel::VideoEncode, _) => mid(max),
                _ => mid(max),
            };
            let clamped = tbl.pin(target);
            targets.push((tbl.domain, clamped));
        }
        targets
    }

    /// Set a specific perf level. AUTO defers per-domain
    /// selection to `apply_inputs`.
    pub fn set_level(&mut self, level: PerfLevel) {
        self.level = level;
    }
}

fn mid(max: u8) -> u8 {
    max / 2
}

// ── PPSMC dispatch (live SMU mailbox push) ─────────────────────────
//
// After Dpm::apply_inputs returns the target (domain, level) list,
// the driver must push:
//   1. PPSMC_MSG_SetWorkloadMask(workload_mask)
//   2. PPSMC_MSG_SetMinDeepSleepDcefclk(target_dcefclk_min)
//   3. PPSMC_MSG_SetSoftMinByFreq / SetSoftMaxByFreq per clock domain.
//
// The SMU mailbox protocol is in amdgpu_smu.rs; here we model the
// per-message dispatch + the param-encoding rules.
//
// LINUX-GAP: the message table that stood here was SMU **13.0.0**'s — Navi3x
// discrete — introduced under the comment "Per Linux Phoenix uses SMU v13_0_4
// — message IDs from pmfw_if/smu_v13_0_0_ppsmc.h", which names the wrong
// header in its own sentence. The two generations share no message space.
//
// The five ids are correct for 13.0.0 and all mean something else on Phoenix
// (`smu_v13_0_4_ppsmc.h`):
//
//   0x19  SetSoftMinByFreq   ->  AllowGfxOff
//   0x1A  SetSoftMaxByFreq   ->  DisallowGfxOff
//   0x1B  SetHardMinByFreq   ->  SetSoftMaxGfxClk
//   0x1C  SetHardMaxByFreq   ->  SetHardMinGfxClk
//   0x24  SetWorkloadMask    ->  SetSoftMinSocclkByFreq
//
// So a soft-min clamp would have told the SMU to allow GFXOFF and a soft-max
// clamp to disallow it — the clocks never clamped, and GFXOFF got toggled on
// every DPM decision instead.
//
// 13.0.4 has no generic by-frequency message and no workload mask at all. It
// has one message per clock, which `amdgpu_smu_v13` carries and this now
// routes through: `set_range_msgs` returns the pair for a domain, and the
// param is a bare frequency in MHz with no domain byte.

/// LINUX-GAP: `PPSMC_MSG_SetWorkloadMask` does not exist on SMU 13.0.4 —
/// there is no workload-hint message in its 0x01..0x30 space. The power
/// profile is expressed on this generation through the per-clock clamps and
/// `SetSoftMinGfxclk`, so [`build_ppsmc_dispatch`] no longer emits one.
/// `Dpm`'s workload mask is still computed and still meaningful to the
/// driver's own policy; it just has nowhere to be sent.
pub const SMU_13_0_4_HAS_NO_WORKLOAD_MASK: () = ();

/// A frequency parameter for SMU 13.0.4's per-clock messages: the frequency
/// in MHz, whole.
///
/// LINUX-GAP: the previous `encode_freq_param` packed a clock-domain id into
/// the top byte, which is 13.0.0's generic-message encoding
/// (`SetSoftMinByFreq` takes `(clk_id << 16) | freq` there, and even that is
/// a sixteen-bit shift, not twenty-four). On 13.0.4 the domain is the message
/// id, so a domain byte in the parameter is a frequency of several hundred
/// million MHz.
pub fn encode_freq_param(freq_mhz: u32) -> u32 {
    freq_mhz
}

/// One PPSMC message produced by the dispatch path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PpsmcMessage {
    pub msg: u32,
    pub param: u32,
}

/// Build the sequence of PPSMC messages needed to push the outcome of
/// `Dpm::apply_inputs` to the SMU mailbox. Caller writes each in turn via the
/// SMU mailbox driver.
///
/// Two messages per domain — soft min then soft max — using the per-clock ids
/// `amdgpu_smu_v13::set_range_msgs` resolves. A domain the generation has no
/// message for (UCLK, VCLK and DCLK are all SMU-managed on this APU) is
/// skipped rather than sent to a neighbouring message id.
///
/// `workload_mask` is accepted and ignored; see
/// [`SMU_13_0_4_HAS_NO_WORKLOAD_MASK`].
pub fn build_ppsmc_dispatch(
    workload_mask: u32,
    targets: &[(ClockDomain, u32)],
) -> Vec<PpsmcMessage> {
    let _ = workload_mask;
    let mut msgs = Vec::with_capacity(targets.len() * 2);
    for (domain, freq_mhz) in targets {
        let Some((set_min, set_max)) = crate::amdgpu_smu_v13::set_range_msgs(*domain) else {
            continue;
        };
        let param = encode_freq_param(*freq_mhz);
        msgs.push(PpsmcMessage {
            msg: set_min,
            param,
        });
        msgs.push(PpsmcMessage {
            msg: set_max,
            param,
        });
    }
    msgs
}

/// Convenience: convert the `Vec<(ClockDomain, u8)>` returned by
/// `Dpm::apply_inputs` into MHz targets by indexing into each
/// domain's level table.
pub fn targets_to_freqs(dpm: &Dpm, targets: &[(ClockDomain, u8)]) -> Vec<(ClockDomain, u32)> {
    let mut out = Vec::with_capacity(targets.len());
    for (domain, level) in targets {
        if let Some(tbl) = dpm.table(*domain) {
            if let Some(mhz) = tbl.levels.get(*level as usize) {
                out.push((*domain, *mhz));
            }
        }
    }
    out
}

// ── Smoke tests ──────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod smoke_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_dpm_table_pin_clamps() -> TestResult {
        let mut t = DpmTable::new(ClockDomain::Gfxclk, alloc::vec![200, 600, 1200, 1800, 2400]);
        if t.level_count() != 5 {
            return TestResult::Fail("level count wrong");
        }
        if t.highest_mhz() != 2400 {
            return TestResult::Fail("highest wrong");
        }
        // Pin within range.
        if t.pin(3) != 3 {
            return TestResult::Fail("pin 3 not 3");
        }
        // Pin above max — clamps.
        if t.pin(99) != 4 {
            return TestResult::Fail("pin 99 didn't clamp to max=4");
        }
        // Soft range.
        t.set_soft_range(1, 3);
        if t.pin(4) != 3 {
            return TestResult::Fail("soft_max=3 not enforced");
        }
        if t.pin(0) != 1 {
            return TestResult::Fail("soft_min=1 not enforced");
        }
        // Swapped range still works.
        t.set_soft_range(3, 1);
        if t.soft_min_level != 1 || t.soft_max_level != 3 {
            return TestResult::Fail("swap didn't normalise");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpm_table_pin_clamps);

    fn smoke_dpm_workload_classifies() -> TestResult {
        // Idle on battery → power saving + default.
        let i = DpmInputs {
            on_battery: true,
            gfx_busy_pct: 5,
            ..Default::default()
        };
        let mask = i.workload_mask();
        if mask & WorkloadBits::POWER_SAVING == 0 {
            return TestResult::Fail("idle+battery missing PS");
        }
        if mask & WorkloadBits::DEFAULT == 0 {
            return TestResult::Fail("default bit always");
        }
        // Game.
        let i = DpmInputs {
            gfx_busy_pct: 85,
            ..Default::default()
        };
        if i.workload_mask() & WorkloadBits::FULLSCREEN_3D == 0 {
            return TestResult::Fail("game missing 3D");
        }
        // Video.
        let i = DpmInputs {
            vcn_decode_busy: true,
            ..Default::default()
        };
        if i.workload_mask() & WorkloadBits::VIDEO == 0 {
            return TestResult::Fail("video missing VIDEO");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpm_workload_classifies);

    fn smoke_dpm_recommended_level() -> TestResult {
        let i = DpmInputs {
            on_battery: true,
            gfx_busy_pct: 5,
            active_crtcs: 1,
            ..Default::default()
        };
        if i.recommended_level() != PerfLevel::Low {
            return TestResult::Fail("idle+battery should rec Low");
        }
        let i = DpmInputs {
            gfx_busy_pct: 90,
            ..Default::default()
        };
        if i.recommended_level() != PerfLevel::Game3d {
            return TestResult::Fail("heavy GFX should rec Game3d");
        }
        let i = DpmInputs {
            vcn_decode_busy: true,
            ..Default::default()
        };
        if i.recommended_level() != PerfLevel::VideoEncode {
            return TestResult::Fail("video should rec VideoEncode");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpm_recommended_level);

    fn smoke_dpm_register_and_set_domain() -> TestResult {
        let mut d = Dpm::new();
        // Domain with no table → NoSuchDomain.
        if d.set_domain(ClockDomain::Gfxclk, 0) != Err(DpmError::NoSuchDomain) {
            return TestResult::Fail("missing domain not flagged");
        }
        d.register_table(DpmTable::new(
            ClockDomain::Gfxclk,
            alloc::vec![100, 500, 1500],
        ));
        // Pin clamps + reports clamped level.
        let l = d.set_domain(ClockDomain::Gfxclk, 99).expect("set");
        if l != 2 {
            return TestResult::Fail("set didn't clamp to 2");
        }
        if d.table(ClockDomain::Gfxclk).unwrap().current_level != 2 {
            return TestResult::Fail("current_level not updated");
        }
        // Register same domain again — replaces.
        d.register_table(DpmTable::new(
            ClockDomain::Gfxclk,
            alloc::vec![200, 600, 1200, 2000],
        ));
        if d.table(ClockDomain::Gfxclk).unwrap().level_count() != 4 {
            return TestResult::Fail("re-register didn't replace");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpm_register_and_set_domain);

    fn smoke_dpm_apply_inputs_low() -> TestResult {
        let mut d = Dpm::new();
        d.register_table(DpmTable::new(
            ClockDomain::Gfxclk,
            alloc::vec![100, 500, 1500],
        ));
        d.register_table(DpmTable::new(
            ClockDomain::Uclk,
            alloc::vec![800, 1200, 1600],
        ));
        d.set_level(PerfLevel::Low);
        let targets = d.apply_inputs(DpmInputs::default());
        if targets.len() != 2 {
            return TestResult::Fail("targets count wrong");
        }
        for (_, l) in &targets {
            if *l != 0 {
                return TestResult::Fail("low should pin to 0");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpm_apply_inputs_low);

    fn smoke_dpm_apply_inputs_game3d() -> TestResult {
        let mut d = Dpm::new();
        d.register_table(DpmTable::new(
            ClockDomain::Gfxclk,
            alloc::vec![100, 500, 1500, 2400],
        ));
        d.register_table(DpmTable::new(
            ClockDomain::Uclk,
            alloc::vec![800, 1200, 1600],
        ));
        d.register_table(DpmTable::new(ClockDomain::Vclk, alloc::vec![300, 600, 900]));
        d.set_level(PerfLevel::Game3d);
        let targets = d.apply_inputs(DpmInputs {
            gfx_busy_pct: 85,
            ..Default::default()
        });
        // GFX / UCLK at max, VCLK at mid.
        let gfx = targets
            .iter()
            .find(|(d, _)| *d == ClockDomain::Gfxclk)
            .unwrap()
            .1;
        if gfx != 3 {
            return TestResult::Fail("GFX not at max");
        }
        let ucl = targets
            .iter()
            .find(|(d, _)| *d == ClockDomain::Uclk)
            .unwrap()
            .1;
        if ucl != 2 {
            return TestResult::Fail("UCLK not at max");
        }
        let vcl = targets
            .iter()
            .find(|(d, _)| *d == ClockDomain::Vclk)
            .unwrap()
            .1;
        if vcl != 1 {
            return TestResult::Fail("VCLK not at mid");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpm_apply_inputs_game3d);

    fn smoke_dpm_apply_inputs_video() -> TestResult {
        let mut d = Dpm::new();
        d.register_table(DpmTable::new(
            ClockDomain::Gfxclk,
            alloc::vec![100, 500, 1500],
        ));
        d.register_table(DpmTable::new(ClockDomain::Vclk, alloc::vec![300, 600, 900]));
        d.register_table(DpmTable::new(ClockDomain::Dclk, alloc::vec![200, 400, 800]));
        d.set_level(PerfLevel::VideoEncode);
        let targets = d.apply_inputs(DpmInputs {
            vcn_decode_busy: true,
            ..Default::default()
        });
        let gfx = targets
            .iter()
            .find(|(d, _)| *d == ClockDomain::Gfxclk)
            .unwrap()
            .1;
        if gfx != 0 {
            return TestResult::Fail("GFX should be low for video");
        }
        let vcl = targets
            .iter()
            .find(|(d, _)| *d == ClockDomain::Vclk)
            .unwrap()
            .1;
        if vcl != 2 {
            return TestResult::Fail("VCLK should be max for video");
        }
        let dcl = targets
            .iter()
            .find(|(d, _)| *d == ClockDomain::Dclk)
            .unwrap()
            .1;
        if dcl != 2 {
            return TestResult::Fail("DCLK should be max for video");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpm_apply_inputs_video);

    fn smoke_dpm_auto_drifts_to_recommended() -> TestResult {
        let mut d = Dpm::new();
        d.register_table(DpmTable::new(
            ClockDomain::Gfxclk,
            alloc::vec![100, 500, 1500, 2400],
        ));
        d.register_table(DpmTable::new(
            ClockDomain::Uclk,
            alloc::vec![800, 1200, 1600],
        ));
        // Start Auto + idle on battery — should drift to Low.
        d.set_level(PerfLevel::Auto);
        let _ = d.apply_inputs(DpmInputs {
            on_battery: true,
            gfx_busy_pct: 5,
            active_crtcs: 1,
            ..Default::default()
        });
        if d.level != PerfLevel::Low {
            return TestResult::Fail("Auto should drift to Low");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpm_auto_drifts_to_recommended);

    // ── PPSMC dispatch ─────────────────────────────────────────

    /// Message ids spelled out from `smu_v13_0_4_ppsmc.h`, with the 13.0.0
    /// value each used to carry alongside, since the whole defect was sending
    /// the other generation's table.
    fn smoke_ppsmc_dispatch_uses_per_clock_messages() -> TestResult {
        let msgs = build_ppsmc_dispatch(
            0x100,
            &[
                (ClockDomain::Gfxclk, 2400),
                // UCLK has no soft min/max message on this generation.
                (ClockDomain::Uclk, 3200),
                (ClockDomain::Socclk, 1200),
            ],
        );
        // Two messages for GFXCLK, none for UCLK, two for SOCCLK. No
        // workload-mask message: 13.0.4 does not have one.
        if msgs.len() != 4 {
            return TestResult::Fail("expected two messages each for GFXCLK and SOCCLK only");
        }
        // SetSoftMinGfxclk 0x09 then SetSoftMaxGfxClk 0x1B. The old table
        // would have sent 0x19 and 0x1A, which are AllowGfxOff and
        // DisallowGfxOff here.
        if msgs[0].msg != 0x09 || msgs[1].msg != 0x1B {
            return TestResult::Fail("GFXCLK clamps are SetSoftMinGfxclk 0x09 / SetSoftMax 0x1B");
        }
        // SetSoftMinSocclkByFreq 0x24 then SetSoftMaxSocclkByFreq 0x1D — the
        // min is *above* the max in the message space, so neither can be
        // derived from the other.
        if msgs[2].msg != 0x24 || msgs[3].msg != 0x1D {
            return TestResult::Fail("SOCCLK clamps are 0x24 min and 0x1D max");
        }
        // The parameter is a bare frequency: a domain byte in the top would
        // make 2400 MHz into hundreds of millions.
        if msgs[0].param != 2400 || msgs[1].param != 2400 {
            return TestResult::Fail("the param is the frequency in MHz, undecorated");
        }
        if msgs[2].param != 1200 {
            return TestResult::Fail("SOCCLK param");
        }
        if encode_freq_param(2400) != 2400 {
            return TestResult::Fail("no domain id is packed into the param");
        }
        // A domain with no message must be skipped, not sent to a neighbour.
        let only_uclk = build_ppsmc_dispatch(0, &[(ClockDomain::Uclk, 3200)]);
        if !only_uclk.is_empty() {
            return TestResult::Fail("UCLK has no clamp message and must emit nothing");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_ppsmc_dispatch_uses_per_clock_messages);

    fn smoke_targets_to_freqs_indexes_level_table() -> TestResult {
        let mut dpm = Dpm::new();
        dpm.register_table(DpmTable::new(
            ClockDomain::Gfxclk,
            alloc::vec![200, 600, 1200, 2400],
        ));
        let targets = alloc::vec![(ClockDomain::Gfxclk, 3)];
        let freqs = targets_to_freqs(&dpm, &targets);
        if freqs.len() != 1 || freqs[0].1 != 2400 {
            return TestResult::Fail("level 3 should index to 2400 MHz");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_targets_to_freqs_indexes_level_table);

    fn smoke_dpm_full_dispatch_pipeline() -> TestResult {
        // Full chain: apply_inputs → targets_to_freqs → build_ppsmc_dispatch.
        let mut dpm = Dpm::new();
        dpm.register_table(DpmTable::new(
            ClockDomain::Gfxclk,
            alloc::vec![200, 1200, 2400],
        ));
        dpm.register_table(DpmTable::new(ClockDomain::Uclk, alloc::vec![800, 3200]));
        dpm.set_level(PerfLevel::High);
        let inputs = DpmInputs {
            gfx_busy_pct: 95,
            ..Default::default()
        };
        let targets = dpm.apply_inputs(inputs);
        let freqs = targets_to_freqs(&dpm, &targets);
        let msgs = build_ppsmc_dispatch(0, &freqs);
        // Two messages per domain that has a clamp message, and no
        // workload-mask message on this generation.
        let clampable = freqs
            .iter()
            .filter(|(d, _)| crate::amdgpu_smu_v13::set_range_msgs(*d).is_some())
            .count();
        if msgs.len() != clampable * 2 {
            return TestResult::Fail("dispatch msg count off");
        }
        // GFX should be at level max=2 → 2400 MHz, via SetSoftMaxGfxClk 0x1B.
        if !msgs.iter().any(|m| m.msg == 0x1B && m.param == 2400) {
            return TestResult::Fail("no SetSoftMaxGfxClk for GFX at 2400");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_dpm_full_dispatch_pipeline);
}
