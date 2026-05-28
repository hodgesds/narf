//! DisplayPort — DPCD addresses, link training state machine.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nouveau_dp.c`**
//!   `nouveau_dp_train` — the orchestration loop that runs CR
//!   then EQ phases.
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/dispnv50/disp.c`**
//!   `nv50_pior_dp_train_*` — Maxwell+ SOR-DP submission of the
//!   training pattern + voltage swing updates.
//! - **Linux `include/drm/display/drm_dp_helper.h`** for the
//!   DPCD addresses; we mirror them as constants without
//!   including the kernel header.
//!
//! DP spec: VESA DisplayPort 1.4/2.x. Training is two phases:
//!
//! 1. **Clock Recovery (CR)** — sink locks its PLL onto the
//!    source's symbol clock. Source sweeps voltage swing +
//!    pre-emphasis levels until CR_DONE is asserted on every lane.
//! 2. **Equalization (EQ)** — sink trains its equalizer. Source
//!    sweeps levels again until CHANNEL_EQ_DONE / SYMBOL_LOCKED /
//!    INTERLANE_ALIGNED hold on every lane.
//!
//! If either phase fails the source reduces link rate / lane
//! count and retries.

#![allow(dead_code)]

// ── DPCD register addresses (subset) ─────────────────────────────

/// DPCD revision register (DPCD 0x000).
pub const DPCD_REV: u32 = 0x0000;
/// Maximum link rate (DPCD 0x001). Encoded as multiples of
/// 270 MHz: 0x06 = 1.62, 0x0A = 2.7, 0x14 = 5.4, 0x1E = 8.1.
pub const DPCD_MAX_LINK_RATE: u32 = 0x0001;
/// Maximum lane count (DPCD 0x002). Bits[4:0] = 1, 2, or 4.
pub const DPCD_MAX_LANE_COUNT: u32 = 0x0002;
/// Receive port 0 capabilities (DPCD 0x008).
pub const DPCD_RECEIVE_PORT0_CAP: u32 = 0x0008;
/// Link bandwidth set (DPCD 0x100) — the link rate the source is
/// currently driving the lanes at.
pub const DPCD_LINK_BW_SET: u32 = 0x0100;
/// Lane count set (DPCD 0x101).
pub const DPCD_LANE_COUNT_SET: u32 = 0x0101;
/// Training pattern set (DPCD 0x102).
pub const DPCD_TRAINING_PATTERN_SET: u32 = 0x0102;
/// Per-lane training-level write (DPCD 0x103..0x106).
pub const DPCD_TRAINING_LANE_SET_BASE: u32 = 0x0103;
/// Link/lane status (DPCD 0x202..0x205).
pub const DPCD_LANE0_1_STATUS: u32 = 0x0202;
pub const DPCD_LANE2_3_STATUS: u32 = 0x0203;
/// Lane-align status updated (DPCD 0x204).
pub const DPCD_LANE_ALIGN_STATUS: u32 = 0x0204;
/// Sink status / IRQ vector (DPCD 0x200..0x201).
pub const DPCD_SINK_COUNT: u32 = 0x0200;

// ── Training-pattern selection (DPCD 0x102 LSB[1:0]) ─────────────

/// Training pattern 0 — link off (idle).
pub const TRAINING_PATTERN_DISABLE: u8 = 0;
/// Training pattern 1 — clock recovery.
pub const TRAINING_PATTERN_1: u8 = 1;
/// Training pattern 2 — equalization (DP 1.1+).
pub const TRAINING_PATTERN_2: u8 = 2;
/// Training pattern 3 — equalization (DP 1.2+).
pub const TRAINING_PATTERN_3: u8 = 3;
/// Training pattern 4 — equalization (DP 1.4+).
pub const TRAINING_PATTERN_4: u8 = 4;

// ── Link rates (DPCD 0x100, 0x001) ───────────────────────────────

/// 1.62 Gbps per lane (RBR — Reduced Bit Rate).
pub const LINK_BW_1_62: u8 = 0x06;
/// 2.7 Gbps per lane (HBR).
pub const LINK_BW_2_7: u8 = 0x0A;
/// 5.4 Gbps per lane (HBR2).
pub const LINK_BW_5_4: u8 = 0x14;
/// 8.1 Gbps per lane (HBR3).
pub const LINK_BW_8_1: u8 = 0x1E;

// ── Per-lane CR/EQ bits (DPCD 0x202/0x203) ───────────────────────
//
// Each pair of nibbles holds: bit 0 = CR_DONE, bit 1 = CE_DONE
// (channel-eq), bit 2 = SYMBOL_LOCKED. Lane 0 is the low nibble of
// 0x202; lane 1 the high; lane 2 the low of 0x203; lane 3 the high.

pub const STATUS_CR_DONE: u8 = 1 << 0;
pub const STATUS_CHANNEL_EQ_DONE: u8 = 1 << 1;
pub const STATUS_SYMBOL_LOCKED: u8 = 1 << 2;

/// Decoded per-lane status nibble.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LaneStatus {
    pub cr_done: bool,
    pub channel_eq_done: bool,
    pub symbol_locked: bool,
}

impl LaneStatus {
    pub const fn decode(nibble: u8) -> Self {
        Self {
            cr_done: nibble & STATUS_CR_DONE != 0,
            channel_eq_done: nibble & STATUS_CHANNEL_EQ_DONE != 0,
            symbol_locked: nibble & STATUS_SYMBOL_LOCKED != 0,
        }
    }
}

/// 4-lane link status decoded from DPCD 0x202/0x203.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinkStatus {
    pub lanes: [LaneStatus; 4],
    /// Interlane alignment ok (DPCD 0x204 bit 0).
    pub interlane_aligned: bool,
}

impl LinkStatus {
    pub fn decode(b202: u8, b203: u8, b204: u8) -> Self {
        Self {
            lanes: [
                LaneStatus::decode(b202 & 0x0F),
                LaneStatus::decode((b202 >> 4) & 0x0F),
                LaneStatus::decode(b203 & 0x0F),
                LaneStatus::decode((b203 >> 4) & 0x0F),
            ],
            interlane_aligned: b204 & 0x01 != 0,
        }
    }

    /// True when CR is locked on every lane in use.
    pub fn cr_done_on(&self, lane_count: u8) -> bool {
        (0..(lane_count as usize)).all(|i| self.lanes[i].cr_done)
    }

    /// True when EQ + symbol-lock + interlane-align all hold.
    pub fn eq_done_on(&self, lane_count: u8) -> bool {
        if !self.interlane_aligned {
            return false;
        }
        (0..(lane_count as usize))
            .all(|i| self.lanes[i].channel_eq_done && self.lanes[i].symbol_locked)
    }
}

// ── Training state machine ───────────────────────────────────────
//
// State machine mirrors `dispnv50/disp.c::nv50_dp_train_*`.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LtPhase {
    /// Send training pattern 1, voltage / pre-emph at 0/0.
    CrStart,
    /// Wait for CR_DONE; bump voltage swing if not converged.
    CrPoll,
    /// CR done; send training pattern 2/3/4 to start EQ.
    EqStart,
    /// Poll EQ status; advance levels if not converged.
    EqPoll,
    /// Both phases passed.
    Done,
    /// Couldn't lock at this rate/count; caller should drop to a
    /// lower link bandwidth or lane count and retry.
    Failed,
}

/// State machine for one training attempt at a given link
/// bandwidth + lane count.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LtMachine {
    pub phase: LtPhase,
    pub link_bw: u8,
    pub lane_count: u8,
    /// Current voltage swing (0..3).
    pub voltage: u8,
    /// Current pre-emphasis (0..voltage).
    pub pre_emph: u8,
    /// How many times we've tried at this swing+pre_emph.
    pub attempts_at_level: u8,
}

impl LtMachine {
    pub const fn new(link_bw: u8, lane_count: u8) -> Self {
        Self {
            phase: LtPhase::CrStart,
            link_bw,
            lane_count,
            voltage: 0,
            pre_emph: 0,
            attempts_at_level: 0,
        }
    }

    /// Advance the machine using the current link-status nibbles.
    ///
    /// `bump_levels` simulates the requested adjust (TRAINING_LANEx
    /// register) — in real hardware the sink writes ADJUST_REQUEST
    /// (DPCD 0x206/0x207) and the source mirrors them. We track
    /// voltage/pre-emph internally.
    pub fn step(&mut self, status: LinkStatus) {
        match self.phase {
            LtPhase::CrStart => {
                // Source has written TP1 + voltage/pre-emph
                // bundle; next step is to poll.
                self.phase = LtPhase::CrPoll;
            }
            LtPhase::CrPoll => {
                if status.cr_done_on(self.lane_count) {
                    self.phase = LtPhase::EqStart;
                    self.attempts_at_level = 0;
                } else {
                    self.attempts_at_level = self.attempts_at_level.saturating_add(1);
                    if self.attempts_at_level >= 5 {
                        // DP spec: max 5 attempts per CR level.
                        if self.voltage >= 3 {
                            self.phase = LtPhase::Failed;
                        } else {
                            self.voltage += 1;
                            self.attempts_at_level = 0;
                        }
                    }
                }
            }
            LtPhase::EqStart => {
                self.phase = LtPhase::EqPoll;
                self.attempts_at_level = 0;
            }
            LtPhase::EqPoll => {
                if !status.cr_done_on(self.lane_count) {
                    // CR slipped — restart from CR.
                    self.phase = LtPhase::CrStart;
                    self.voltage = 0;
                    self.pre_emph = 0;
                    return;
                }
                if status.eq_done_on(self.lane_count) {
                    self.phase = LtPhase::Done;
                } else {
                    self.attempts_at_level = self.attempts_at_level.saturating_add(1);
                    if self.attempts_at_level >= 5 {
                        self.phase = LtPhase::Failed;
                    }
                }
            }
            LtPhase::Done | LtPhase::Failed => {}
        }
    }
}

/// Map sink-reported MAX_LINK_RATE to a human-readable Gbps.
pub const fn link_rate_gbps_x10(bw: u8) -> u32 {
    match bw {
        LINK_BW_1_62 => 16,
        LINK_BW_2_7 => 27,
        LINK_BW_5_4 => 54,
        LINK_BW_8_1 => 81,
        _ => 0,
    }
}
