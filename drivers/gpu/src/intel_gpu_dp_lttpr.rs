//! Per-hop 8b/10b link training through LTTPRs in non-transparent mode
//! (Linux 7.4 `intel_dp_link_training.c`: `intel_dp_link_train_all_phys`,
//! `intel_dp_link_train_phy`), for the display-14+ external DP route under
//! the strict boot option `narf.intel.uhbr=1` ([`super::uhbr::BOOT_OPTION`]).
//!
//! With repeaters switched to non-transparent mode
//! ([`super::uhbr::init_lttpr_and_dprx_caps`]) each hop trains on its own:
//! the LTTPR next to the source first (`DP_PHY_LTTPR(count - 1)`), then each
//! one downstream of it, then the DPRX, every PHY with clock recovery
//! (`intel_dp_link_training_clock_recovery`) and channel equalization
//! (`intel_dp_link_training_channel_equalization`) at its own registers
//! (`DP_TRAINING_PATTERN_SET_PHY_REPEATER`, `DP_TRAINING_LANE0_SET_PHY_REPEATER`,
//! `drm_dp_dpcd_read_phy_link_status`), and its pattern disabled after it
//! (`intel_dp_disable_dpcd_training_pattern`). The source sends every hop's
//! pattern but drives its own levels only for the hop it feeds
//! (`intel_dp_phy_is_downstream_of_source`); the drive maxima of a farther
//! hop are those of the LTTPR transmitting into it
//! (`intel_dp_lttpr_voltage_max`, `intel_dp_lttpr_preemph_max`).
//!
//! Everything is DPCD over an [`AuxChannel`]; the route's
//! `crate::intel_gpu_modeset::training::TrainingAux` turns the pattern and
//! level writes into source programming
//! (`intel_dp_program_link_training_pattern`, `encoder->set_signal_levels`).
//!
//! Not ported here: `intel_dp_post_lt_adj_req` (the DPRX's
//! `DP_POST_LT_ADJ_REQ_GRANTED` phase), which the end-to-end 8b/10b
//! training does not run either.

use crate::dp_aux::{AuxChannel, AuxError};
use crate::dp_link_training::{
    LaneTune, LinkError, LinkRate as TrainRate, ReceiverTraining, TrainedLink, VSwingPe,
};

use super::uhbr::{Clock, LttprInit, DP_LTTPR_STRIDE};

/// `DP_TRAINING_PATTERN_SET` / `DP_TRAINING_LANE0_SET`.
const DP_TRAINING_PATTERN_SET: u32 = 0x102;
const DP_TRAINING_LANE0_SET: u32 = 0x103;
/// `DP_LANE0_1_STATUS` (the six-byte DPRX link status).
const DP_LANE0_1_STATUS: u32 = 0x202;
/// `DP_TRAINING_PATTERN_SET_PHY_REPEATER1`, `DP_TRAINING_LANE0_SET_PHY_REPEATER1`
/// and `DP_LANE0_1_STATUS_PHY_REPEATER1` (the five-byte LTTPR status).
pub const DP_TRAINING_PATTERN_SET_PHY_REPEATER1: u32 = 0xf_0010;
pub const DP_TRAINING_LANE0_SET_PHY_REPEATER1: u32 = 0xf_0011;
pub const DP_LANE0_1_STATUS_PHY_REPEATER1: u32 = 0xf_0030;
/// `DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER1`.
const DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER1: u32 = 0xf_0020;
/// `DP_TRAINING_AUX_RD_MASK`.
const DP_TRAINING_AUX_RD_MASK: u8 = 0x7f;
/// `DP_TRAINING_PATTERN_1` and `_4`, `DP_LINK_SCRAMBLING_DISABLE`.
pub const DP_TRAINING_PATTERN_1: u8 = 1;
pub const DP_TRAINING_PATTERN_4: u8 = 7;
pub const DP_LINK_SCRAMBLING_DISABLE: u8 = 1 << 5;
/// `DP_TRAINING_LANEx_SET` fields.
const DP_TRAIN_VOLTAGE_SWING_MASK: u8 = 0x3;
const DP_TRAIN_MAX_SWING_REACHED: u8 = 1 << 2;
const DP_TRAIN_PRE_EMPHASIS_SHIFT: u8 = 3;
const DP_TRAIN_PRE_EMPHASIS_MASK: u8 = 0x3 << DP_TRAIN_PRE_EMPHASIS_SHIFT;
const DP_TRAIN_MAX_PRE_EMPHASIS_REACHED: u8 = 1 << 5;
/// `DP_TRANSMITTER_CAPABILITY_PHY_REPEATER1` (byte 1 of the PHY caps) bits.
const DP_VOLTAGE_SWING_LEVEL_3_SUPPORTED: u8 = 1 << 0;
const DP_PRE_EMPHASIS_LEVEL_3_SUPPORTED: u8 = 1 << 1;
/// The source's drive maxima: `intel_ddi_dp_voltage_max` (the last of the
/// ten `index_to_dp_signal_levels` entries a display-14+ DP table holds,
/// swing level 3) and `intel_ddi_dp_preemph_max` (level 3).
pub const SOURCE_VOLTAGE_MAX: u8 = 3;
pub const SOURCE_PREEMPH_MAX: u8 = 3;

/// One PHY on the link (`enum drm_dp_phy`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Phy {
    /// `DP_PHY_DPRX`.
    Dprx,
    /// `DP_PHY_LTTPR(i)`.
    Lttpr(u8),
}

impl Phy {
    fn offset(self) -> u32 {
        match self {
            Self::Dprx => 0,
            Self::Lttpr(i) => u32::from(i) * DP_LTTPR_STRIDE,
        }
    }

    /// `intel_dp_training_pattern_set_reg`.
    pub fn pattern_reg(self) -> u32 {
        match self {
            Self::Dprx => DP_TRAINING_PATTERN_SET,
            Self::Lttpr(_) => DP_TRAINING_PATTERN_SET_PHY_REPEATER1 + self.offset(),
        }
    }

    /// `DP_TRAINING_LANE0_SET` / `DP_TRAINING_LANE0_SET_PHY_REPEATER`.
    pub fn lane0_set_reg(self) -> u32 {
        match self {
            Self::Dprx => DP_TRAINING_LANE0_SET,
            Self::Lttpr(_) => DP_TRAINING_LANE0_SET_PHY_REPEATER1 + self.offset(),
        }
    }
}

/// What the per-hop training needs to know about the link.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Dp14Link {
    /// `crtc_state->lane_count`: 1, 2 or 4.
    pub lanes: u8,
    /// The DPRX's `DP_DPCD_REV` (the clock recovery tries).
    pub dprx_rev: u8,
    /// The DPRX's clock recovery and channel equalization delays
    /// (`drm_dp_read_clock_recovery_delay` / `drm_dp_read_channel_eq_delay`
    /// for `DP_PHY_DPRX`), microseconds.
    pub dprx_cr_delay_us: u32,
    pub dprx_eq_delay_us: u32,
    /// `intel_dp_training_pattern` for the DPRX, with
    /// `DP_LINK_SCRAMBLING_DISABLE` for TPS2/3.
    pub dprx_eq_pattern: u8,
    /// The repeaters in non-transparent mode and their PHY caps.
    pub lttpr: LttprInit,
}

impl Dp14Link {
    fn count(&self) -> u8 {
        self.lttpr.count
    }

    /// `intel_dp_phy_is_downstream_of_source`.
    pub fn downstream_of_source(&self, phy: Phy) -> bool {
        self.count() == 0 || phy == Phy::Lttpr(self.count() - 1)
    }

    /// The PHY transmitting into `phy` when that is an LTTPR (`dp_phy + 1`),
    /// as its index.
    fn upstream_lttpr(&self, phy: Phy) -> u8 {
        match phy {
            Phy::Dprx => 0,
            Phy::Lttpr(i) => i + 1,
        }
    }

    /// `intel_dp_phy_voltage_max`: the source's, or the upstream LTTPR's
    /// (`drm_dp_lttpr_voltage_swing_level_3_supported`, else level 2).
    pub fn voltage_max(&self, phy: Phy) -> u8 {
        if self.downstream_of_source(phy) {
            return SOURCE_VOLTAGE_MAX;
        }
        let caps = self.lttpr.phy_caps[usize::from(self.upstream_lttpr(phy))];
        if caps[1] & DP_VOLTAGE_SWING_LEVEL_3_SUPPORTED != 0 {
            3
        } else {
            2
        }
    }

    /// `intel_dp_phy_preemph_max`: the source's, or the upstream LTTPR's
    /// (`drm_dp_lttpr_pre_emphasis_level_3_supported`, else level 2).
    pub fn preemph_max(&self, phy: Phy) -> u8 {
        if self.downstream_of_source(phy) {
            return SOURCE_PREEMPH_MAX;
        }
        let caps = self.lttpr.phy_caps[usize::from(self.upstream_lttpr(phy))];
        if caps[1] & DP_PRE_EMPHASIS_LEVEL_3_SUPPORTED != 0 {
            3
        } else {
            2
        }
    }

    /// `drm_dp_read_clock_recovery_delay`: 100 us for an LTTPR.
    fn cr_delay_us(&self, phy: Phy) -> u32 {
        match phy {
            Phy::Dprx => self.dprx_cr_delay_us,
            Phy::Lttpr(_) => 100,
        }
    }

    /// `intel_dp_training_pattern`: an LTTPR supports TPS4 (display 10+
    /// sends it), which runs scrambled.
    fn eq_pattern(&self, phy: Phy) -> u8 {
        match phy {
            Phy::Dprx => self.dprx_eq_pattern,
            Phy::Lttpr(_) => DP_TRAINING_PATTERN_4,
        }
    }
}

/// `drm_dp_read_channel_eq_delay` for `phy`: the DPRX's, or the LTTPR's
/// `DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER` (`__8b10b_channel_eq_delay_us`:
/// 400 us for 0, else units of 4 ms; a failed read is 400 us).
fn eq_delay_us<A: AuxChannel + ?Sized>(aux: &mut A, link: &Dp14Link, phy: Phy) -> u32 {
    let Phy::Lttpr(_) = phy else {
        return link.dprx_eq_delay_us;
    };
    let mut value = [0u8];
    if aux
        .dpcd_read(
            DP_TRAINING_AUX_RD_INTERVAL_PHY_REPEATER1 + phy.offset(),
            &mut value,
        )
        .is_err()
    {
        return 400;
    }
    match value[0] & DP_TRAINING_AUX_RD_MASK {
        0 => 400,
        interval => u32::from(interval) * 4_000,
    }
}

/// `drm_dp_dpcd_read_phy_link_status`: the DPRX's six bytes, or an LTTPR's
/// five with a zero `DP_SINK_STATUS` slot inserted.
pub fn read_phy_link_status<A: AuxChannel + ?Sized>(
    aux: &mut A,
    phy: Phy,
) -> Result<[u8; 6], AuxError> {
    let mut status = [0u8; 6];
    match phy {
        Phy::Dprx => aux.dpcd_read(DP_LANE0_1_STATUS, &mut status)?,
        Phy::Lttpr(_) => {
            let mut raw = [0u8; 5];
            aux.dpcd_read(DP_LANE0_1_STATUS_PHY_REPEATER1 + phy.offset(), &mut raw)?;
            status[..3].copy_from_slice(&raw[..3]);
            status[4..].copy_from_slice(&raw[3..]);
        }
    }
    Ok(status)
}

fn lane_nibble(status: &[u8; 6], lane: usize) -> u8 {
    (status[lane / 2] >> ((lane & 1) * 4)) & 0xf
}

/// `drm_dp_clock_recovery_ok`.
pub fn clock_recovery_ok(status: &[u8; 6], lanes: u8) -> bool {
    (0..usize::from(lanes)).all(|l| lane_nibble(status, l) & 0x1 != 0)
}

/// `drm_dp_channel_eq_ok`: `DP_INTERLANE_ALIGN_DONE` and every lane's
/// CR, channel EQ and symbol lock.
pub fn channel_eq_ok(status: &[u8; 6], lanes: u8) -> bool {
    status[2] & 0x1 != 0 && (0..usize::from(lanes)).all(|l| lane_nibble(status, l) & 0x7 == 0x7)
}

/// `drm_dp_get_adjust_request_voltage` / `_pre_emphasis` for `lane`, as
/// levels.
fn adjust_request(status: &[u8; 6], lane: usize) -> (u8, u8) {
    let byte = status[4 + lane / 2];
    let shift = (lane & 1) * 4;
    ((byte >> shift) & 0x3, (byte >> (shift + 2)) & 0x3)
}

/// `dp_voltage_max`: the highest swing level a pre-emphasis level allows.
const fn dp_voltage_max(preemph: u8) -> u8 {
    match preemph {
        0 => 3,
        1 => 2,
        2 => 1,
        _ => 0,
    }
}

/// `intel_dp_get_lane_adjust_vswing_preemph` (display 10+: per-lane levels,
/// `has_per_lane_signal_levels`) for every `train_set` lane: the request of
/// `min(lane, lanes - 1)`, the pre-emphasis capped at the PHY's maximum
/// (flagged `DP_TRAIN_MAX_PRE_EMPHASIS_REACHED`), the swing capped by it
/// (`dp_voltage_max`) and at the PHY's maximum (flagged
/// `DP_TRAIN_MAX_SWING_REACHED`). Returns whether anything changed
/// (`intel_dp_get_adjust_train`).
pub fn get_adjust_train(
    link: &Dp14Link,
    phy: Phy,
    status: &[u8; 6],
    train_set: &mut [u8; 4],
) -> bool {
    let (vmax, pmax) = (link.voltage_max(phy), link.preemph_max(phy));
    let mut changed = false;
    for (lane, set) in train_set.iter_mut().enumerate() {
        let (mut v, p) = adjust_request(status, lane.min(usize::from(link.lanes.max(1)) - 1));
        let mut p_bits = p << DP_TRAIN_PRE_EMPHASIS_SHIFT;
        let p_level = if p >= pmax {
            p_bits = (pmax << DP_TRAIN_PRE_EMPHASIS_SHIFT) | DP_TRAIN_MAX_PRE_EMPHASIS_REACHED;
            pmax
        } else {
            p
        };
        v = v.min(dp_voltage_max(p_level));
        let v_bits = if v >= vmax {
            vmax | DP_TRAIN_MAX_SWING_REACHED
        } else {
            v
        };
        let new = v_bits | p_bits;
        if *set != new {
            *set = new;
            changed = true;
        }
    }
    changed
}

/// `intel_dp_lane_max_vswing_reached` for every lane
/// (`intel_dp_link_max_vswing_reached`): the swing flagged at its maximum
/// with swing + pre-emphasis 3.
fn max_vswing_reached(train_set: &[u8; 4], lanes: u8) -> bool {
    train_set[..usize::from(lanes)].iter().all(|&set| {
        let v = set & DP_TRAIN_VOLTAGE_SWING_MASK;
        let p = (set & DP_TRAIN_PRE_EMPHASIS_MASK) >> DP_TRAIN_PRE_EMPHASIS_SHIFT;
        set & DP_TRAIN_MAX_SWING_REACHED != 0 && v + p == 3
    })
}

/// `intel_dp_adjust_request_changed` on 8b/10b.
fn adjust_request_changed(old: &[u8; 6], new: &[u8; 6], lanes: u8) -> bool {
    (0..usize::from(lanes)).any(|lane| adjust_request(old, lane) != adjust_request(new, lane))
}

/// `intel_dp_set_link_train`: `DP_TRAINING_PATTERN_SET` (or the PHY
/// repeater's) with the lanes' `DP_TRAINING_LANEx_SET` after it.
fn set_link_train<A: AuxChannel + ?Sized>(
    aux: &mut A,
    phy: Phy,
    pattern: u8,
    train_set: &[u8; 4],
    lanes: u8,
) -> Result<(), AuxError> {
    let mut buf = [0u8; 5];
    buf[0] = pattern;
    buf[1..].copy_from_slice(train_set);
    aux.dpcd_write(phy.pattern_reg(), &buf[..1 + usize::from(lanes)])
}

/// `intel_dp_update_link_train`.
fn update_link_train<A: AuxChannel + ?Sized>(
    aux: &mut A,
    phy: Phy,
    train_set: &[u8; 4],
    lanes: u8,
) -> Result<(), AuxError> {
    aux.dpcd_write(phy.lane0_set_reg(), &train_set[..usize::from(lanes)])
}

/// Why a hop failed (each a Linux `lt_err` / `lt_dbg` exit).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HopFailure {
    /// A DPCD access the sequence needs failed.
    Aux(AuxError),
    /// The same adjust request five times.
    SameVoltage,
    /// Every lane at its maximum swing without clock recovery.
    MaxVoltage,
    /// Clock recovery took every try (10 from DPCD 1.4, else 80).
    CrTries,
    /// Clock recovery was lost during channel equalization.
    CrLost,
    /// Channel equalization took its five tries.
    EqTries,
}

impl From<AuxError> for HopFailure {
    fn from(e: AuxError) -> Self {
        Self::Aux(e)
    }
}

/// A failed per-hop training: the PHY and why.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HopError {
    pub phy: Phy,
    pub failure: HopFailure,
}

/// `intel_dp_link_training_clock_recovery` on `phy`.
fn clock_recovery<A: AuxChannel + ?Sized, C: Clock>(
    aux: &mut A,
    clock: &mut C,
    link: &Dp14Link,
    phy: Phy,
    train_set: &mut [u8; 4],
) -> Result<(), HopFailure> {
    let lanes = link.lanes;
    let delay = u64::from(link.cr_delay_us(phy));
    // intel_dp_reset_link_train: zero levels, TPS1 without scrambling.
    *train_set = [0; 4];
    set_link_train(
        aux,
        phy,
        DP_TRAINING_PATTERN_1 | DP_LINK_SCRAMBLING_DISABLE,
        train_set,
        lanes,
    )?;
    let max_tries = if link.dprx_rev >= 0x14 { 10 } else { 80 };
    let mut old = [0u8; 6];
    let mut voltage_tries = 1;
    let mut max_reached = false;
    for _ in 0..max_tries {
        clock.sleep_us(delay);
        let status = read_phy_link_status(aux, phy)?;
        if clock_recovery_ok(&status, lanes) {
            return Ok(());
        }
        if voltage_tries == 5 {
            return Err(HopFailure::SameVoltage);
        }
        if max_reached {
            return Err(HopFailure::MaxVoltage);
        }
        get_adjust_train(link, phy, &status, train_set);
        update_link_train(aux, phy, train_set, lanes)?;
        if adjust_request_changed(&old, &status, lanes) {
            voltage_tries = 1;
        } else {
            voltage_tries += 1;
        }
        old = status;
        if max_vswing_reached(train_set, lanes) {
            max_reached = true;
        }
    }
    Err(HopFailure::CrTries)
}

/// `intel_dp_link_training_channel_equalization` on `phy`.
fn channel_equalization<A: AuxChannel + ?Sized, C: Clock>(
    aux: &mut A,
    clock: &mut C,
    link: &Dp14Link,
    phy: Phy,
    train_set: &mut [u8; 4],
) -> Result<(), HopFailure> {
    let lanes = link.lanes;
    let delay = u64::from(eq_delay_us(aux, link, phy));
    set_link_train(aux, phy, link.eq_pattern(phy), train_set, lanes)?;
    for _ in 0..5 {
        clock.sleep_us(delay);
        let status = read_phy_link_status(aux, phy)?;
        if !clock_recovery_ok(&status, lanes) {
            return Err(HopFailure::CrLost);
        }
        if channel_eq_ok(&status, lanes) {
            return Ok(());
        }
        get_adjust_train(link, phy, &status, train_set);
        update_link_train(aux, phy, train_set, lanes)?;
    }
    Err(HopFailure::EqTries)
}

/// `intel_dp_link_train_phy`: clock recovery, then channel equalization.
fn train_phy<A: AuxChannel + ?Sized, C: Clock>(
    aux: &mut A,
    clock: &mut C,
    link: &Dp14Link,
    phy: Phy,
    train_set: &mut [u8; 4],
) -> Result<(), HopError> {
    clock_recovery(aux, clock, link, phy, train_set)
        .and_then(|()| channel_equalization(aux, clock, link, phy, train_set))
        .map_err(|failure| HopError { phy, failure })
}

/// `intel_dp_link_train_all_phys` after `intel_dp_prepare_link_train`: each
/// LTTPR from the one next to the source (`DP_PHY_LTTPR(count - 1)`) down,
/// its pattern disabled after it, then the DPRX if every hop trained, and
/// the DPRX's pattern disabled however it ended. Returns the levels the
/// source drives (the train set of the hop next to it), as the route's
/// trained levels.
pub fn train_all_phys<A: AuxChannel + ?Sized, C: Clock>(
    aux: &mut A,
    clock: &mut C,
    link: &Dp14Link,
) -> Result<VSwingPe, HopError> {
    let mut train_set = [0u8; 4];
    let mut source = [0u8; 4];
    let mut result = Ok(());
    for i in (0..link.count()).rev() {
        let phy = Phy::Lttpr(i);
        result = train_phy(aux, clock, link, phy, &mut train_set);
        if link.downstream_of_source(phy) {
            source = train_set;
        }
        let _ = aux.dpcd_write(phy.pattern_reg(), &[0]);
        if result.is_err() {
            break;
        }
    }
    if result.is_ok() {
        result = train_phy(aux, clock, link, Phy::Dprx, &mut train_set);
        if link.downstream_of_source(Phy::Dprx) {
            source = train_set;
        }
    }
    let _ = aux.dpcd_write(Phy::Dprx.pattern_reg(), &[0]);
    result?;
    let mut levels = VSwingPe::default();
    for (tune, set) in levels.lanes.iter_mut().zip(source) {
        *tune = LaneTune {
            swing: set & DP_TRAIN_VOLTAGE_SWING_MASK,
            pre_emph: (set & DP_TRAIN_PRE_EMPHASIS_MASK) >> DP_TRAIN_PRE_EMPHASIS_SHIFT,
        };
    }
    Ok(levels)
}

/// The [`Dp14Link`] of an 8b/10b link at `lanes` through `lttpr`, the
/// DPRX's side from the route's receiver training (its revision, delays and
/// equalization pattern).
pub fn link_for(
    receiver: &ReceiverTraining,
    dprx_rev: u8,
    lanes: u8,
    lttpr: LttprInit,
) -> Dp14Link {
    let (cr, eq) = receiver.delays_us();
    Dp14Link {
        lanes,
        dprx_rev,
        dprx_cr_delay_us: cr,
        dprx_eq_delay_us: eq,
        dprx_eq_pattern: receiver.equalization_pattern(),
        lttpr,
    }
}

/// `DP_DOWNSPREAD_CTRL` (with `DP_MAIN_LINK_CHANNEL_CODING_SET` after it),
/// `DP_SET_ANSI_8B10B`, `DP_LINK_BW_SET` and `DP_LANE_COUNT_ENHANCED_FRAME_EN`.
const DP_DOWNSPREAD_CTRL: u32 = 0x107;
const DP_SET_ANSI_8B10B: u8 = 1 << 0;
const DP_LINK_BW_SET: u32 = 0x100;
const DP_LANE_COUNT_ENHANCED_FRAME_EN: u8 = 1 << 7;
/// `DP_SET_POWER` / `DP_SET_POWER_D0`.
const DP_SET_POWER: u32 = 0x600;
const DP_SET_POWER_D0: u8 = 1;

/// The route's 8b/10b training through `lttpr` (repeaters in
/// non-transparent mode): the sink powered up, then per configuration
/// `intel_dp_prepare_link_train`'s sink half
/// (`intel_dp_link_training_set_mode`: `DP_DOWNSPREAD_CTRL` 0 and
/// `DP_SET_ANSI_8B10B`; `intel_dp_link_training_set_bw`: `DP_LINK_BW_SET`
/// and `DP_LANE_COUNT_SET` with the receiver's enhanced framing) and
/// [`train_all_phys`]. A failed configuration steps down the route's ladder
/// (the rate, then half the lanes from the requested rate, as the
/// end-to-end training's) and the caller handles a trained configuration
/// below the requested one as it does for that training.
pub fn train_link<A: AuxChannel + ?Sized, C: Clock>(
    aux: &mut A,
    clock: &mut C,
    rate: TrainRate,
    lanes: u8,
    receiver: &ReceiverTraining,
    dprx_rev: u8,
    lttpr: LttprInit,
) -> Result<TrainedLink, LinkError> {
    if !matches!(lanes, 1 | 2 | 4) {
        return Err(LinkError::Aborted);
    }
    aux.dpcd_write(DP_SET_POWER, &[DP_SET_POWER_D0])?;
    let mut cur_rate = rate;
    let mut cur_lanes = lanes;
    loop {
        let framing = if receiver.enhanced_framing {
            DP_LANE_COUNT_ENHANCED_FRAME_EN
        } else {
            0
        };
        aux.dpcd_write(DP_DOWNSPREAD_CTRL, &[0, DP_SET_ANSI_8B10B])?;
        aux.dpcd_write(DP_LINK_BW_SET, &[cur_rate as u8, cur_lanes | framing])?;
        let link = link_for(receiver, dprx_rev, cur_lanes, lttpr);
        match train_all_phys(aux, clock, &link) {
            Ok(vswing_pe) => {
                return Ok(TrainedLink {
                    rate: cur_rate,
                    lanes: cur_lanes,
                    vswing_pe,
                })
            }
            Err(HopError {
                failure: HopFailure::Aux(e),
                ..
            }) => return Err(LinkError::AuxFailure(e)),
            Err(e) => {
                if let Some(lower) = cur_rate.next_lower() {
                    cur_rate = lower;
                } else if cur_lanes > 1 {
                    cur_lanes /= 2;
                    cur_rate = rate;
                } else {
                    return Err(match e.failure {
                        HopFailure::CrLost | HopFailure::EqTries => LinkError::EqFailed(0),
                        _ => LinkError::CrFailed(0),
                    });
                }
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_dp_lttpr_tests.rs"]
mod tests;
