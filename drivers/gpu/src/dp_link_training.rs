//! DisplayPort link-training state machine — clean-room.
//!
//! Reference: VESA DisplayPort 1.4a Standard, §3.5 "Link
//! Training Sequence". Public document. Implements the
//! source-side state machine that drives a sink through clock
//! recovery (CR) + channel equalization (EQ).
//!   <https://vesa.org/vesa-standards/>
//!
//! The spec-aligned helpers (`train_clock_recovery`,
//! `train_channel_equalization`, `train_link`) mirror the
//! algorithm used by the Linux DRM helpers and the AMD DC link
//! training core, both GPL-2.0-or-later and compatible with
//! NARF's post-2026-05-20 license:
//!   - `drivers/gpu/drm/display/drm_dp_helper.c`
//!     (drm_dp_link_train_clock_recovery_delay,
//!      drm_dp_link_train_channel_eq_delay,
//!      drm_dp_clock_recovery_ok, drm_dp_channel_eq_ok)
//!   - `drivers/gpu/drm/amd/display/dc/link/protocols/
//!      link_dp_training_8b_10b.c`
//!     (perform_clock_recovery_sequence, perform_channel_equalization_sequence)
//!
//! ## State machine
//!
//! ```text
//! Idle ──(start)──> ClockRecovery ──(CR locked)──> Equalization
//!  ^                     │                              │
//!  │                     │ (CR fail)                    │ (EQ fail)
//!  │                     v                              v
//!  └────────────── Failed ←───────────────────────  Failed
//!                                                       │
//!  Idle <──(EQ locked)── Trained ←────────────(symbol locked)
//! ```
//!
//! At each step the source:
//! 1. Writes `LINK_BW_SET` + `LANE_COUNT_SET` (Idle → CR start).
//! 2. Sets `TRAINING_PATTERN_SET = TPS1` and zero voltage swing /
//!    pre-emphasis on each lane.
//! 3. Reads `LANE0_1_STATUS` + `LANE2_3_STATUS` from the sink
//!    after a 100 µs settling delay.
//! 4. If all lanes report `CR_DONE`, advance to EQ. Otherwise
//!    bump voltage swing per lane (up to MAX_LEVEL = 3) and
//!    retry; after 10 retries, fail.
//! 5. EQ phase: swap to `TPS2` / `TPS3`, poll for `EQ_DONE`,
//!    `CHANNEL_EQ_DONE`, `SYMBOL_LOCKED`, and
//!    `INTERLANE_ALIGN_DONE` (in `LANE_ALIGN_STATUS_UPDATED`).
//! 6. On full success, set `TRAINING_PATTERN_SET = 0` (training
//!    off, normal-data scrambling on) and report `Trained`.
//!
//! ## Transport agnosticism
//!
//! The state machine drives `dp_aux::AuxChannel` for every
//! DPCD read/write. A real DCN-AUX transport, a virtio-gpu
//! pass-through, or a stub used by tests all implement
//! `AuxChannel` — same training logic runs against any of them.

use crate::dp_aux::{AuxChannel, AuxError};

// DPCD register addresses we touch (DPCD §3.3).
const DPCD_LINK_BW_SET: u32 = 0x0_0100;
const DPCD_LANE_COUNT_SET: u32 = 0x0_0101;
const DPCD_TRAINING_PATTERN_SET: u32 = 0x0_0102;
const DPCD_TRAINING_LANE0_SET: u32 = 0x0_0103;
const DPCD_LANE0_1_STATUS: u32 = 0x0_0202;
const DPCD_LANE2_3_STATUS: u32 = 0x0_0203;
const DPCD_LANE_ALIGN_STATUS_UPDATED: u32 = 0x0_0204;

/// Training pattern slot values per DPCD `TRAINING_PATTERN_SET`.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TrainingPattern {
    None = 0,
    Tps1 = 1,
    Tps2 = 2,
    Tps3 = 3,
    Tps4 = 7,
}

/// Link-training state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrainingState {
    /// Idle: no training in flight; either pre-start or post-trained.
    Idle,
    /// Clock-recovery phase (TPS1 + voltage-swing tuning).
    ClockRecovery,
    /// Channel-equalization phase (TPS2/3 + EQ + symbol lock).
    Equalization,
    /// Both phases passed; sink is on-line.
    Trained,
    /// Training failed permanently. Caller falls back to a lower
    /// link rate / fewer lanes and retries.
    Failed,
}

/// Per-lane voltage swing + pre-emphasis levels. DP §3.5.1.3:
/// each lane has 4 swing levels (0..3) and 4 pre-emp levels.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LaneTune {
    pub swing: u8,
    pub pre_emph: u8,
}

const MAX_LANES: usize = 4;
const MAX_RETRIES_PER_PHASE: u32 = 10;

/// Parameters supplied by the source (caller).
#[derive(Copy, Clone, Debug)]
pub struct TrainingParams {
    /// Link rate code per DPCD: 0x06 = RBR (1.62 Gbps), 0x0A =
    /// HBR (2.7), 0x14 = HBR2 (5.4), 0x1E = HBR3 (8.1).
    pub link_bw_set: u8,
    /// Lane count: 1, 2, or 4. DPCD bits[4:0]. Bit 7 (enhanced
    /// framing) is OR'd in by the state machine.
    pub lane_count: u8,
}

/// DP link-rate codes per DPCD §3.3.5. Ordered low → high so
/// `LinkRate::next_lower` walks the documented fallback ladder.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkRate {
    /// 1.62 Gbps per lane — RBR (Reduced Bit Rate). Mandatory
    /// floor; DP 1.0 baseline.
    Rbr = 0x06,
    /// 2.7 Gbps — HBR.
    Hbr = 0x0A,
    /// 5.4 Gbps — HBR2.
    Hbr2 = 0x14,
    /// 8.1 Gbps — HBR3.
    Hbr3 = 0x1E,
}

impl LinkRate {
    pub fn from_dpcd_byte(v: u8) -> Option<Self> {
        match v {
            0x06 => Some(LinkRate::Rbr),
            0x0A => Some(LinkRate::Hbr),
            0x14 => Some(LinkRate::Hbr2),
            0x1E => Some(LinkRate::Hbr3),
            _ => None,
        }
    }
    /// One step lower on the fallback ladder. RBR has no lower
    /// step → `None` (caller's training has truly failed).
    pub fn next_lower(self) -> Option<Self> {
        match self {
            LinkRate::Hbr3 => Some(LinkRate::Hbr2),
            LinkRate::Hbr2 => Some(LinkRate::Hbr),
            LinkRate::Hbr => Some(LinkRate::Rbr),
            LinkRate::Rbr => None,
        }
    }
}

/// Drive link training with the documented DP §3.5.4 fallback
/// policy: on `Failed`, fall to the next-lower link rate and
/// retry. If RBR fails too, halve the lane count and retry from
/// the highest rate. Returns the parameters that succeeded
/// (caller programs DCN with these), or `Failed` after the full
/// ladder bottoms out.
pub fn run_with_fallback<A: AuxChannel>(
    aux: &mut A,
    initial_bw: LinkRate,
    initial_lanes: u8,
    delay_us: impl Fn(u32) + Copy,
) -> Result<TrainingParams, AuxError> {
    let mut bw = initial_bw;
    let mut lanes = match initial_lanes {
        1 | 2 | 4 => initial_lanes,
        _ => {
            return Ok(TrainingParams {
                link_bw_set: bw as u8,
                lane_count: 0,
            })
        }
    };
    loop {
        let params = TrainingParams {
            link_bw_set: bw as u8,
            lane_count: lanes,
        };
        match run(aux, params, delay_us)? {
            TrainingState::Trained => return Ok(params),
            _ => {
                // Step down link rate first.
                if let Some(lower) = bw.next_lower() {
                    bw = lower;
                    continue;
                }
                // Bottom of rate ladder. Halve lane count and
                // restart from the original rate.
                if lanes > 1 {
                    lanes /= 2;
                    bw = initial_bw;
                    continue;
                }
                // Single lane at RBR has nowhere lower to go.
                return Ok(TrainingParams {
                    link_bw_set: 0,
                    lane_count: 0,
                });
            }
        }
    }
}

/// Drives the link-training state machine to completion. Returns
/// `Trained` on success, `Failed` on permanent failure.
///
/// `aux` is borrowed across the transaction; the implementation
/// owns retries / DEFER backoff.
///
/// `delay_us(n)` is a caller-supplied microsecond sleep — the
/// state machine needs ~100 µs settling between voltage-swing
/// adjustments. Stage-5 callers typically pass a busy-loop
/// closure; later transport layers can wire timer-based sleeps.
pub fn run<A: AuxChannel>(
    aux: &mut A,
    params: TrainingParams,
    delay_us: impl Fn(u32),
) -> Result<TrainingState, AuxError> {
    // Step 1: program LINK_BW_SET + LANE_COUNT_SET. Bit 7 of
    // LANE_COUNT_SET is `enhanced_framing_en`; we always set it
    // (DP 1.2+).
    aux.dpcd_write(DPCD_LINK_BW_SET, &[params.link_bw_set])?;
    aux.dpcd_write(DPCD_LANE_COUNT_SET, &[params.lane_count | 0x80])?;

    // Step 2: enter Clock Recovery.
    let n_lanes = (params.lane_count & 0x1F) as usize;
    if n_lanes == 0 || n_lanes > MAX_LANES {
        return Ok(TrainingState::Failed);
    }
    let mut tunes = [LaneTune::default(); MAX_LANES];
    aux.dpcd_write(DPCD_TRAINING_PATTERN_SET, &[TrainingPattern::Tps1 as u8])?;
    write_lane_tunes(aux, &tunes[..n_lanes])?;

    // Step 3: poll LANE_STATUS for CR_DONE on every lane. Spec
    // budget: 10 retries with voltage-swing bumps.
    let mut cr_state = TrainingState::ClockRecovery;
    for _ in 0..MAX_RETRIES_PER_PHASE {
        delay_us(100);
        let status = read_lane_status(aux)?;
        if all_cr_done(&status, n_lanes) {
            cr_state = TrainingState::Equalization;
            break;
        }
        // CR not done — bump swing on each lane that hasn't
        // reached CR yet, capped at 3 (MAX_LEVEL).
        for (i, t) in tunes.iter_mut().enumerate().take(n_lanes) {
            if !cr_done_lane(&status, i) {
                if t.swing >= 3 {
                    return Ok(TrainingState::Failed);
                }
                t.swing += 1;
            }
        }
        write_lane_tunes(aux, &tunes[..n_lanes])?;
    }
    if cr_state != TrainingState::Equalization {
        // Out of retries.
        aux.dpcd_write(DPCD_TRAINING_PATTERN_SET, &[0])?;
        return Ok(TrainingState::Failed);
    }

    // Step 5: enter Equalization. Use TPS2 by default; HBR2+
    // links use TPS3 — caller can extend this. Stage-5 sticks
    // with TPS2 since that's the lowest-common-denominator and
    // all DP 1.2+ sinks accept it.
    aux.dpcd_write(DPCD_TRAINING_PATTERN_SET, &[TrainingPattern::Tps2 as u8])?;
    let mut eq_state = TrainingState::Equalization;
    for _ in 0..MAX_RETRIES_PER_PHASE {
        delay_us(400); // EQ phase settling: 400 µs per spec.
        let status = read_lane_status(aux)?;
        let align = aux_read_one(aux, DPCD_LANE_ALIGN_STATUS_UPDATED)?;
        if all_eq_done(&status, n_lanes) && (align & 1) != 0 {
            eq_state = TrainingState::Trained;
            break;
        }
        // EQ retry: bump pre-emphasis where lanes haven't
        // reached symbol-lock.
        for (i, t) in tunes.iter_mut().enumerate().take(n_lanes) {
            if !eq_done_lane(&status, i) {
                if t.pre_emph >= 3 {
                    return Ok(TrainingState::Failed);
                }
                t.pre_emph += 1;
            }
        }
        write_lane_tunes(aux, &tunes[..n_lanes])?;
    }
    // Step 6: training off (or fail).
    aux.dpcd_write(DPCD_TRAINING_PATTERN_SET, &[0])?;
    Ok(eq_state)
}

// ── helpers ────────────────────────────────────────────────────────

/// Encode + write per-lane tune values. DPCD `TRAINING_LANE0_SET`
/// is one byte per lane: bits[1:0] = swing, bits[4:3] = pre-emph.
fn write_lane_tunes<A: AuxChannel>(aux: &mut A, tunes: &[LaneTune]) -> Result<(), AuxError> {
    let mut bytes = [0u8; MAX_LANES];
    for (i, t) in tunes.iter().enumerate() {
        bytes[i] = (t.swing & 0x3)
                 | (((t.swing & 0x3) == 3) as u8) << 2 // MAX_REACHED bit
                 | ((t.pre_emph & 0x3) << 3);
    }
    aux.dpcd_write(DPCD_TRAINING_LANE0_SET, &bytes[..tunes.len()])?;
    Ok(())
}

/// Lane-status read: returns 2 bytes covering all 4 lanes
/// (LANE0_1_STATUS at +0x202, LANE2_3_STATUS at +0x203).
fn read_lane_status<A: AuxChannel>(aux: &mut A) -> Result<[u8; 2], AuxError> {
    let mut buf = [0u8; 2];
    aux.dpcd_read(DPCD_LANE0_1_STATUS, &mut buf[..1])?;
    aux.dpcd_read(DPCD_LANE2_3_STATUS, &mut buf[1..])?;
    Ok(buf)
}

/// Read a single byte from DPCD.
fn aux_read_one<A: AuxChannel>(aux: &mut A, addr: u32) -> Result<u8, AuxError> {
    let mut b = [0u8];
    aux.dpcd_read(addr, &mut b)?;
    Ok(b[0])
}

/// Per-lane status nibble layout (DPCD §3.3.7):
///   bit 0: CR_DONE
///   bit 1: CHANNEL_EQ_DONE
///   bit 2: SYMBOL_LOCKED
///   bit 3: reserved
fn lane_nibble(status: &[u8; 2], lane: usize) -> u8 {
    let byte = status[lane / 2];
    if lane & 1 == 0 {
        byte & 0x0F
    } else {
        (byte >> 4) & 0x0F
    }
}

fn cr_done_lane(status: &[u8; 2], lane: usize) -> bool {
    lane_nibble(status, lane) & 0x01 != 0
}

fn eq_done_lane(status: &[u8; 2], lane: usize) -> bool {
    let n = lane_nibble(status, lane);
    // EQ phase requires CR_DONE + CHANNEL_EQ_DONE + SYMBOL_LOCKED.
    n & 0x07 == 0x07
}

fn all_cr_done(status: &[u8; 2], n_lanes: usize) -> bool {
    (0..n_lanes).all(|i| cr_done_lane(status, i))
}

fn all_eq_done(status: &[u8; 2], n_lanes: usize) -> bool {
    (0..n_lanes).all(|i| eq_done_lane(status, i))
}

// ── Spec-aligned link-training API ──────────────────────────────────
//
// The helpers below mirror the algorithm documented in DP 1.4a
// §3.5.1 closely enough to drive real silicon: the sink's
// ADJUST_REQUEST_LANE registers are honored on every retry, and
// retries are capped at 5 per phase with the "swing-MAX twice
// counts" rule.

// DPCD addresses used by the spec-aligned helpers (DPCD §3.3).
const DPCD_ADJUST_REQUEST_LANE0_1: u32 = 0x0_0206;
const DPCD_ADJUST_REQUEST_LANE2_3: u32 = 0x0_0207;
const DPCD_SET_POWER: u32 = 0x0_0600;

const DP_SET_POWER_D0: u8 = 0x01;
const DP_SET_POWER_MASK: u8 = 0x03;

/// Maximum retry count per phase, per DP 1.4a §3.5.1.2.2 (CR) and
/// §3.5.1.2.3 (EQ).
const MAX_PHASE_ATTEMPTS: u8 = 5;

/// Maximum vswing / pre-emphasis level — DP 1.4a §3.5.1.3.
const MAX_VSWING: u8 = 3;
const MAX_PRE_EMPH: u8 = 3;

/// Per-lane drive parameters: voltage swing + pre-emphasis level
/// per DP §3.5.1.3, indexed by lane (0..=3). The `Default` value
/// (all zero / level 0) is the starting point for every training
/// attempt.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VSwingPe {
    pub lanes: [LaneTune; MAX_LANES],
}

/// Successful training result. Caller programs DCN with these.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TrainedLink {
    pub rate: LinkRate,
    pub lanes: u8,
    pub vswing_pe: VSwingPe,
}

/// Link-training failure modes. Carries the phase the failure
/// happened in so a fallback driver can tell CR-from-EQ failures
/// apart (the spec recommends different fallback policy for each:
/// CR failure → step rate down; EQ failure → reduce lane count).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// Clock-recovery phase exhausted its 5 attempts. The contained
    /// byte is `LANE0_1_STATUS` for diagnostics.
    CrFailed(u8),
    /// Channel-EQ phase exhausted its 5 attempts.
    EqFailed(u8),
    /// Caller aborted (e.g. HPD dropped mid-train).
    Aborted,
    /// AUX-level failure — sink unreachable.
    AuxFailure(AuxError),
}

impl From<AuxError> for LinkError {
    fn from(e: AuxError) -> Self {
        LinkError::AuxFailure(e)
    }
}

/// Decode the per-lane ADJUST_REQUEST fields the sink asks for
/// after each polled status read. Two bytes cover four lanes:
///
/// ```text
/// byte 0 (LANE0_1):
///   bits[1:0]  VOLTAGE_SWING_LANE0
///   bits[3:2]  PRE_EMPHASIS_LANE0
///   bits[5:4]  VOLTAGE_SWING_LANE1
///   bits[7:6]  PRE_EMPHASIS_LANE1
/// byte 1 (LANE2_3): same layout for lanes 2/3.
/// ```
fn decode_adjust_request(adjust: &[u8; 2], n_lanes: usize) -> VSwingPe {
    let mut out = VSwingPe::default();
    for lane in 0..n_lanes {
        let byte = adjust[lane / 2];
        let shift = (lane & 1) * 4;
        out.lanes[lane].swing = (byte >> shift) & 0x3;
        out.lanes[lane].pre_emph = (byte >> (shift + 2)) & 0x3;
    }
    out
}

/// Read both ADJUST_REQUEST bytes.
fn read_adjust_request<A: AuxChannel>(aux: &mut A) -> Result<[u8; 2], AuxError> {
    let mut buf = [0u8; 2];
    aux.dpcd_read(DPCD_ADJUST_REQUEST_LANE0_1, &mut buf[..1])?;
    aux.dpcd_read(DPCD_ADJUST_REQUEST_LANE2_3, &mut buf[1..])?;
    Ok(buf)
}

/// Write per-lane TRAINING_LANEx_SET from a VSwingPe. Sets the
/// MAX_SWING_REACHED / MAX_PRE_EMPH_REACHED flags as required by
/// the spec when a lane has been maxed out.
fn write_vswing_pe<A: AuxChannel>(
    aux: &mut A,
    vswing_pe: &VSwingPe,
    n_lanes: usize,
) -> Result<(), AuxError> {
    let mut bytes = [0u8; MAX_LANES];
    for i in 0..n_lanes {
        let t = vswing_pe.lanes[i];
        let mut b = t.swing & 0x3;
        if t.swing >= MAX_VSWING {
            b |= 1 << 2; // MAX_SWING_REACHED
        }
        b |= (t.pre_emph & 0x3) << 3;
        if t.pre_emph >= MAX_PRE_EMPH {
            b |= 1 << 5; // MAX_PRE_EMPH_REACHED
        }
        bytes[i] = b;
    }
    aux.dpcd_write(DPCD_TRAINING_LANE0_SET, &bytes[..n_lanes])
}

/// Map a link rate to the spec-recommended training-pattern for the
/// EQ phase. HBR2/HBR3 prefer TPS3 (DP 1.2) or TPS4 (DP 1.4) when
/// the sink advertises support; this floor uses TPS2 for RBR/HBR
/// and TPS3 for HBR2/HBR3 — the broadest compatibility envelope.
fn eq_pattern_for_rate(rate: LinkRate) -> TrainingPattern {
    match rate {
        LinkRate::Rbr | LinkRate::Hbr => TrainingPattern::Tps2,
        LinkRate::Hbr2 | LinkRate::Hbr3 => TrainingPattern::Tps3,
    }
}

/// Clock-recovery phase per DP 1.4a §3.5.1.2.2.
///
/// Drives the sink through CR with at most 5 retries. After each
/// 100 µs settle, reads LANEx_y_STATUS and ADJUST_REQUEST_LANEx.
/// If every active lane reports `CR_DONE`, returns the converged
/// drive levels. Otherwise applies the sink's requested vswing/pe
/// and retries. The "same vswing twice" rule: if the sink keeps
/// asking for the same MAX vswing, count it as two retries.
///
/// Reference: Linux
/// `drivers/gpu/drm/amd/display/dc/link/protocols/link_dp_training_8b_10b.c`
/// `perform_clock_recovery_sequence`.
pub fn train_clock_recovery<A: AuxChannel>(
    aux: &mut A,
    rate: LinkRate,
    lanes: u8,
    delay_us: impl Fn(u32),
) -> Result<VSwingPe, LinkError> {
    let n_lanes = lanes as usize;
    if n_lanes == 0 || n_lanes > MAX_LANES {
        return Err(LinkError::Aborted);
    }

    // Program LINK_BW_SET + LANE_COUNT_SET + enhanced framing.
    aux.dpcd_write(DPCD_LINK_BW_SET, &[rate as u8])?;
    aux.dpcd_write(DPCD_LANE_COUNT_SET, &[(lanes & 0x1F) | 0x80])?;

    // Start with level-0 drive on every lane and pattern TPS1.
    let mut vswing_pe = VSwingPe::default();
    write_vswing_pe(aux, &vswing_pe, n_lanes)?;
    aux.dpcd_write(DPCD_TRAINING_PATTERN_SET, &[TrainingPattern::Tps1 as u8])?;

    // Track repeats of the same MAX vswing — DP 1.4a §3.5.1.2.2.
    let mut max_swing_repeat = 0u8;
    let mut prev_swing0 = u8::MAX;

    for _ in 0..MAX_PHASE_ATTEMPTS {
        delay_us(100);
        let status = read_lane_status(aux)?;
        if all_cr_done(&status, n_lanes) {
            return Ok(vswing_pe);
        }

        // Honor the sink's ADJUST_REQUEST.
        let adjust = read_adjust_request(aux)?;
        let requested = decode_adjust_request(&adjust, n_lanes);

        // If every active lane has the same swing as last round
        // AND that swing is MAX, count this as a saturated retry.
        if requested.lanes[0].swing == prev_swing0 && requested.lanes[0].swing >= MAX_VSWING {
            max_swing_repeat += 1;
            if max_swing_repeat >= 2 {
                return Err(LinkError::CrFailed(status[0]));
            }
        } else {
            max_swing_repeat = 0;
        }
        prev_swing0 = requested.lanes[0].swing;

        vswing_pe = requested;
        write_vswing_pe(aux, &vswing_pe, n_lanes)?;
    }

    // Exhausted attempts without CR.
    let status = read_lane_status(aux)?;
    Err(LinkError::CrFailed(status[0]))
}

/// Channel-equalization phase per DP 1.4a §3.5.1.2.3.
///
/// Assumes CR has just succeeded with `start_vswing_pe`. Switches
/// the sink to TPS2/TPS3 (rate-dependent), polls up to 5 times
/// for symbol-lock + interlane-align, honoring ADJUST_REQUEST on
/// each iteration. On success the sink is in normal data mode
/// (TRAINING_PATTERN_SET = 0) and the link is ready for stream.
///
/// Reference: Linux
/// `drivers/gpu/drm/amd/display/dc/link/protocols/link_dp_training_8b_10b.c`
/// `perform_channel_equalization_sequence`.
pub fn train_channel_equalization<A: AuxChannel>(
    aux: &mut A,
    rate: LinkRate,
    lanes: u8,
    start_vswing_pe: VSwingPe,
    delay_us: impl Fn(u32),
) -> Result<VSwingPe, LinkError> {
    let n_lanes = lanes as usize;
    if n_lanes == 0 || n_lanes > MAX_LANES {
        return Err(LinkError::Aborted);
    }
    let mut vswing_pe = start_vswing_pe;

    aux.dpcd_write(
        DPCD_TRAINING_PATTERN_SET,
        &[eq_pattern_for_rate(rate) as u8],
    )?;
    write_vswing_pe(aux, &vswing_pe, n_lanes)?;

    for _ in 0..MAX_PHASE_ATTEMPTS {
        delay_us(400);
        let status = read_lane_status(aux)?;
        let align = aux_read_one(aux, DPCD_LANE_ALIGN_STATUS_UPDATED)?;

        // EQ requires CR still-set AND CHANNEL_EQ_DONE AND
        // SYMBOL_LOCKED on every active lane, AND
        // INTERLANE_ALIGN_DONE in LANE_ALIGN_STATUS_UPDATED bit 0.
        if all_cr_done(&status, n_lanes) && all_eq_done(&status, n_lanes) && (align & 1) != 0 {
            // Training off; sink enters normal operation.
            aux.dpcd_write(DPCD_TRAINING_PATTERN_SET, &[TrainingPattern::None as u8])?;
            return Ok(vswing_pe);
        }

        // If CR was lost during EQ, the spec says fail immediately
        // and fall back — not retry EQ. Caller's fallback handles.
        if !all_cr_done(&status, n_lanes) {
            return Err(LinkError::EqFailed(status[0]));
        }

        // Honor sink's drive-level request.
        let adjust = read_adjust_request(aux)?;
        vswing_pe = decode_adjust_request(&adjust, n_lanes);
        write_vswing_pe(aux, &vswing_pe, n_lanes)?;
    }

    let status = read_lane_status(aux)?;
    Err(LinkError::EqFailed(status[0]))
}

/// Walk a single (rate, lanes) attempt: power on, CR, EQ. On any
/// failure returns the LinkError so `train_link` can decide
/// whether to step down.
fn train_one<A: AuxChannel>(
    aux: &mut A,
    rate: LinkRate,
    lanes: u8,
    delay_us: impl Fn(u32) + Copy,
) -> Result<TrainedLink, LinkError> {
    let vswing_pe = train_clock_recovery(aux, rate, lanes, delay_us)?;
    let vswing_pe = train_channel_equalization(aux, rate, lanes, vswing_pe, delay_us)?;
    Ok(TrainedLink {
        rate,
        lanes,
        vswing_pe,
    })
}

/// Full link-training driver. Brings the sink out of D3 (SET_POWER
/// = D0), tries `(requested_rate, requested_lanes)` first, then
/// walks the documented fallback ladder on failure:
///
/// 1. Step the link rate down one notch (HBR3 → HBR2 → HBR → RBR).
/// 2. When RBR fails, halve the lane count and restart from the
///    originally requested rate.
/// 3. When 1 lane at RBR fails too, training is permanently
///    failed — the cable or sink is broken.
///
/// On every attempt the source resets TRAINING_PATTERN_SET to 0
/// before returning, so the sink never lingers in a training
/// pattern after a failed train round.
///
/// Reference: Linux
/// `drivers/gpu/drm/amd/display/dc/link/protocols/link_dp_training.c`
/// `dp_perform_link_training` + `decide_fallback_link_setting`.
pub fn train_link<A: AuxChannel>(
    aux: &mut A,
    requested_rate: LinkRate,
    requested_lanes: u8,
    delay_us: impl Fn(u32) + Copy,
) -> Result<TrainedLink, LinkError> {
    let lanes = match requested_lanes {
        1 | 2 | 4 => requested_lanes,
        _ => return Err(LinkError::Aborted),
    };

    // Power the sink up to D0 before training.
    aux.dpcd_write(DPCD_SET_POWER, &[DP_SET_POWER_D0 & DP_SET_POWER_MASK])?;

    let mut rate = requested_rate;
    let mut cur_lanes = lanes;
    // Defensive default: each loop iteration reassigns `last_err` before
    // it can be read, so the initializer is a deliberate dead store.
    #[allow(unused_assignments)]
    let mut last_err = LinkError::Aborted;

    loop {
        match train_one(aux, rate, cur_lanes, delay_us) {
            Ok(trained) => return Ok(trained),
            Err(e) => {
                last_err = e;
                // Always disable any leftover training pattern
                // before walking the ladder.
                let _ = aux.dpcd_write(DPCD_TRAINING_PATTERN_SET, &[TrainingPattern::None as u8]);
                if let Some(lower) = rate.next_lower() {
                    rate = lower;
                    continue;
                }
                if cur_lanes > 1 {
                    cur_lanes /= 2;
                    rate = requested_rate;
                    continue;
                }
                return Err(last_err);
            }
        }
    }
}
