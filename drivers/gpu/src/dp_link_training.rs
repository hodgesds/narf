//! DisplayPort link-training state machine — clean-room.
//!
//! Reference: VESA DisplayPort 1.4a Standard, §3.5 "Link
//! Training Sequence". Public document. Implements the
//! source-side state machine that drives a sink through clock
//! recovery (CR) + channel equalization (EQ).
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
const DPCD_LINK_BW_SET:                 u32 = 0x0_0100;
const DPCD_LANE_COUNT_SET:              u32 = 0x0_0101;
const DPCD_TRAINING_PATTERN_SET:        u32 = 0x0_0102;
const DPCD_TRAINING_LANE0_SET:          u32 = 0x0_0103;
const DPCD_LANE0_1_STATUS:              u32 = 0x0_0202;
const DPCD_LANE2_3_STATUS:              u32 = 0x0_0203;
const DPCD_LANE_ALIGN_STATUS_UPDATED:   u32 = 0x0_0204;

/// Training pattern slot values per DPCD `TRAINING_PATTERN_SET`.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TrainingPattern {
    None  = 0,
    Tps1  = 1,
    Tps2  = 2,
    Tps3  = 3,
    Tps4  = 7,
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
#[derive(Copy, Clone, Debug, Default)]
pub struct LaneTune {
    pub swing:    u8,
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
    pub lane_count:  u8,
}

/// DP link-rate codes per DPCD §3.3.5. Ordered low → high so
/// `LinkRate::next_lower` walks the documented fallback ladder.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkRate {
    /// 1.62 Gbps per lane — RBR (Reduced Bit Rate). Mandatory
    /// floor; DP 1.0 baseline.
    Rbr  = 0x06,
    /// 2.7 Gbps — HBR.
    Hbr  = 0x0A,
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
            _    => None,
        }
    }
    /// One step lower on the fallback ladder. RBR has no lower
    /// step → `None` (caller's training has truly failed).
    pub fn next_lower(self) -> Option<Self> {
        match self {
            LinkRate::Hbr3 => Some(LinkRate::Hbr2),
            LinkRate::Hbr2 => Some(LinkRate::Hbr),
            LinkRate::Hbr  => Some(LinkRate::Rbr),
            LinkRate::Rbr  => None,
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
    aux:        &mut A,
    initial_bw: LinkRate,
    initial_lanes: u8,
    delay_us:   impl Fn(u32) + Copy,
) -> Result<TrainingParams, AuxError> {
    let mut bw    = initial_bw;
    let mut lanes = match initial_lanes { 1 | 2 | 4 => initial_lanes, _ => return Ok(TrainingParams { link_bw_set: bw as u8, lane_count: 0 }) };
    loop {
        let params = TrainingParams {
            link_bw_set: bw as u8,
            lane_count:  lanes,
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
                    link_bw_set: 0, lane_count: 0,
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
    aux:      &mut A,
    params:   TrainingParams,
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
                if t.swing >= 3 { return Ok(TrainingState::Failed); }
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
        let align  = aux_read_one(aux, DPCD_LANE_ALIGN_STATUS_UPDATED)?;
        if all_eq_done(&status, n_lanes) && (align & 1) != 0 {
            eq_state = TrainingState::Trained;
            break;
        }
        // EQ retry: bump pre-emphasis where lanes haven't
        // reached symbol-lock.
        for (i, t) in tunes.iter_mut().enumerate().take(n_lanes) {
            if !eq_done_lane(&status, i) {
                if t.pre_emph >= 3 { return Ok(TrainingState::Failed); }
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
fn write_lane_tunes<A: AuxChannel>(aux: &mut A, tunes: &[LaneTune])
    -> Result<(), AuxError>
{
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
    if lane & 1 == 0 { byte & 0x0F } else { (byte >> 4) & 0x0F }
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
