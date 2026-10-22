//! Linux modules/freesync BTR hysteresis, multiplier and per-VUPDATE state.
use super::{drr, effective_range, Drr, Timing, VrrRange};

const MAX_MARGIN_US: u32 = 2500;
const DRIFT_MARGIN_US: u32 = 2000;

/// Admission-derived LFC range. BTR requires at least a 2:1 effective range;
/// no timing or memory clock changes are inferred from render cadence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LfcConfig {
    pub(super) timing: Timing,
    pub(super) base: Drr,
    min_us: u32,
    max_us: u32,
    midpoint_us: u32,
    margin_us: u32,
}
impl LfcConfig {
    pub fn new(timing: &Timing, range: VrrRange) -> Option<Self> {
        let (min, max) = effective_range(timing, range)?;
        if max < min.checked_mul(2)? {
            return None;
        }
        let min_us = u32::try_from(1_000_000_000_000u64.checked_div(max)?).ok()?;
        let max_us = u32::try_from(1_000_000_000_000u64.checked_div(min)?).ok()?;
        let midpoint_us = min_us.checked_add(max_us)? / 2;
        if midpoint_us == 0 || min_us == 0 {
            return None;
        }
        Some(Self {
            timing: *timing,
            base: drr(timing, range)?,
            min_us,
            max_us,
            midpoint_us,
            margin_us: max_us.checked_sub(2 * min_us)?.min(MAX_MARGIN_US),
        })
    }
    pub fn timing(self) -> Timing {
        self.timing
    }
    pub fn base(self) -> Drr {
        self.base
    }
    /// calc_v_total_from_duration: HDMI ceilings, DP floors, both clamped
    /// to nominal and the effective duration range.
    pub fn total_from_duration(self, duration_us: u32, hdmi: bool) -> Option<u32> {
        let duration = duration_us.clamp(self.min_us, self.max_us);
        let numerator = u64::from(duration) * u64::from(self.timing.pixel_clock_khz);
        let denominator = u64::from(self.timing.h_total) * 1000;
        let total = if hdmi {
            numerator.div_ceil(denominator)
        } else {
            numerator / denominator
        };
        let total = u32::try_from(total).ok()?.max(self.timing.v_total);
        (total <= super::MAX_V_TOTAL).then_some(total)
    }
}

/// Retained BTR state of one VRR stream (mod_vrr_params.btr). Advancing it
/// requires an observed real frame; scheduler time alone never counts one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lfc {
    pub config: LfcConfig,
    pub active: bool,
    pub inserted_duration_us: u32,
    pub frames_to_insert: u32,
    pub frame_counter: u32,
}
impl Lfc {
    pub fn new(config: LfcConfig) -> Self {
        Self {
            config,
            active: false,
            inserted_duration_us: 0,
            frames_to_insert: 0,
            frame_counter: 0,
        }
    }
    pub fn reset(&mut self) {
        *self = Self::new(self.config);
    }
    /// apply_below_the_range. A returned range applies immediately on BTR
    /// exit; entering/changing BTR waits for the next VUPDATE, as Linux.
    pub fn preflip(&mut self, last_render_us: u32) -> Option<Drr> {
        let c = self.config;
        let max_render = c.max_us - c.margin_us;
        if u64::from(last_render_us) + u64::from(c.margin_us / 2) < u64::from(max_render) {
            self.active = false;
        } else if u64::from(last_render_us) > u64::from(max_render) + u64::from(c.margin_us / 2) {
            self.active = true;
        }
        if !self.active {
            self.reset();
            return Some(c.base);
        }
        let ceil =
            u32::try_from(u64::from(last_render_us).div_ceil(u64::from(c.midpoint_us))).ok()?;
        let floor = last_render_us / c.midpoint_us;
        let delta_ceil = if ceil > 0 {
            c.midpoint_us.abs_diff(last_render_us / ceil)
        } else {
            u32::MAX
        };
        let delta_floor = if floor > 0 {
            c.midpoint_us.abs_diff(last_render_us / floor)
        } else {
            u32::MAX
        };
        let mut frames = if ceil > 0 && last_render_us / ceil < c.min_us {
            floor
        } else if floor < 2 || delta_ceil < delta_floor {
            ceil
        } else {
            floor
        };
        if self.frames_to_insert != 0 && delta_ceil.abs_diff(delta_floor) < DRIFT_MARGIN_US {
            let duration = last_render_us / self.frames_to_insert;
            if duration < max_render && duration > c.min_us {
                frames = self.frames_to_insert;
            }
        }
        if frames > 0 && last_render_us / frames < c.min_us {
            frames -= u32::from(frames > 1);
        }
        self.inserted_duration_us = if frames > 0 {
            last_render_us / frames
        } else {
            0
        }
        .max(c.min_us);
        self.frames_to_insert = frames;
        self.frame_counter = frames;
        None
    }
    /// mod_freesync_handle_v_update's BTR branch. During inserted frames
    /// MIN=MAX makes the same retained surface scan repeatedly; once the
    /// count reaches zero the ordinary variable range resumes.
    pub fn vupdate(&mut self, hdmi: bool) -> Option<Drr> {
        if !self.active {
            return None;
        }
        let first = self.frames_to_insert == self.frame_counter;
        let repeat = if first {
            Some(
                self.config
                    .total_from_duration(self.inserted_duration_us, hdmi)?,
            )
        } else {
            None
        };
        self.frame_counter = self.frame_counter.saturating_sub(1);
        if self.frame_counter == 0 {
            Some(self.config.base)
        } else {
            repeat.map(|total| Drr {
                v_total_min: total,
                v_total_max: total,
            })
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_freesync_lfc_tests.rs"]
mod tests;
