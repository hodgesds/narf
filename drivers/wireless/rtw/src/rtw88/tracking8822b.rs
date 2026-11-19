// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822BE ("B22") thermal power tracking: Linux 7.3-rc4
//! `rtw8822b.c::rtw8822b_pwr_track` (`power_track_type` 0) over
//! `rtw8822b_phy_pwrtrack`, `_pwrtrack_path`, `_pwrtrack_set`,
//! `_pwrtrack_set_pwr` and `_txagc_swing_offset`, with the `phy.c`
//! helpers `rtw_phy_config_swing_table` (2.4 GHz and 5 GHz), `rtw_phy_pwrtrack_avg`
//! (`DECLARE_EWMA(thermal, 10, 4)`), `_thermal_changed`, `_get_delta`,
//! `_get_pwridx` and `_need_iqk` (`iqk_threshold` 8) and the
//! `rtw8822b_pwr_track_type0_tbl` rows (2.4 GHz CCK/OFDM per path; 5 GHz
//! `pwrtrk_5ga/5gb` for `RTW_PWR_TRK_5G_1..3`, which are all equal).
//!
//! `rtw_phy_get_tx_power_index` is replaced by the per-path, per-rate coded
//! index the committed program actually wrote (`N2BP`, or the bound `N2BO`
//! record off channel 1, plus the bound `N2BH`/`N2BB`/`N2BV` words). A
//! current rate that program never wrote (beyond the covered DESC_RATE
//! range, or zero on both paths) skips the pass ([`Pass::Skipped`], no
//! register access) rather than deriving an index or failing the dm
//! program. The dm watchdog drives [`Tracker::pass`] when
//! the signed `N2BD` record enables `dm::PWR_TRACK`; every register access
//! runs inside that record's authority (which nests `N2BS`, `N2BP`, `N2BQ`
//! and current policy). A meter sample outside the `N2BD` thermal window or
//! the `N2BP` windows, or a swing delta beyond the `N2BD` power bounds, is
//! refused before any write. When `rtw_phy_pwrtrack_need_iqk` fires the
//! watchdog runs `rtw8822b_do_iqk` as an associated-station maintenance
//! under its own separately signed `N2BW` record ([`KIND`]), with TX paused
//! and drained and RXDMA parked first; this module never issues IQK.
use super::{
    dm::{Authority, Ewma},
    firmware_transport::{enclosed, Error, Io},
    qualification::{Kind, PAYLOAD},
    radio8822b,
};

/// RTL8822BE associated-station IQK maintenance (`N2BW`, generic layout,
/// tag `W`). Payload: bytes 0..32 the exact `N2BD` request identity it was
/// qualified with (the IQK runs only from that dm program), bytes 32/33 the
/// thermal window [lo, hi] the associated IQK was measured over, zero tail.
pub(super) static KIND: Kind = Kind {
    tag: b'W',
    stem: "power-track",
    source: SOURCE,
    admit,
};
/// Hashed into every `N2BW` request (`qualification::request`).
pub(super) const SOURCE: &[u8] = b"RTL8822BE N2BW: rtw8822b.c rtw8822b_phy_pwrtrack iqk label: phy.c rtw_phy_pwrtrack_need_iqk |thermal_avg[A]-thermal_meter_k|>=iqk_threshold 8 then thermal_meter_k=avg; rtw8822b_do_iqk clear0 segment0 H2C, RF-A RF08 abcde 300x20ms then RF08 clear, 1bf0 low8/reload16 zero (Linux only logs); before the H2C: TXPAUSE 522=ff, every TX ring rp==wp, packet core quiet, FIFOPAGE_INFO 230..23c configured==free 64/64/64/64, RXPKT_NUM 284 RW_RELEASE then RXDMA_IDLE; after: RXDMA release, TXPAUSE 0, retire copied receive admission; bound to the exact N2BD identity; no invented coefficient restore";

fn admit(did: u16, p: &[u8; PAYLOAD]) -> bool {
    did == 0xb822
        && p[..32] != [0; 32]
        && p[32] <= p[33]
        && p[33] <= 63
        && p[34..].iter().all(|&v| v == 0)
}

/// The `N2BW` record applies only to the exact `N2BD` program it names.
pub(super) fn binds(iqk: &super::qualification::Grant, dm: &super::qualification::Grant) -> bool {
    iqk.is(&KIND) && dm.is(&super::dm::KIND) && iqk.payload()[..32] == dm.source_identity().0
}

/// The `N2BW` measured thermal window.
pub(super) fn window(iqk: &super::qualification::Grant) -> [u8; 2] {
    [iqk.payload()[32], iqk.payload()[33]]
}

/// Associated-station IQK maintenance steps (PCI `Native`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// TXPAUSE 0xff and RXDMA release request; reports quiet.
    Begin,
    /// TX rings, packet core, FIFO pages and RXDMA idle.
    Quiet,
    /// The `rtw8822b_do_iqk` H2C (clear 0, segment 0).
    Submit,
    /// RXDMA released and TXPAUSE cleared after a quiet IQK.
    Finish,
}

/// Measured envelope of the `N2BD` record (`dm::Bounds`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Limits {
    pub(super) thermal: [u8; 2],
    pub(super) up: u8,
    pub(super) down: u8,
}

/// `RTW_PWR_TRK_TBL_SZ`.
const TABLE: usize = 30;
/// `rtw8822b_pwrtrk_2ga_p`.
const OFDM_A_P: [u8; TABLE] = [
    0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14,
    14, 15,
];
/// `rtw8822b_pwrtrk_2gb_p`.
const OFDM_B_P: [u8; TABLE] = [
    0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 12, 13,
    13,
];
/// `rtw8822b_pwrtrk_2ga_n` = `_2gb_n` = `_2g_cck_a_n` = `_2g_cck_b_n`.
const N: [u8; TABLE] = [
    0, 1, 1, 1, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 7, 7, 8, 8, 9, 9, 9, 10, 10, 11, 11, 11, 12,
];
/// `rtw8822b_pwrtrk_2g_cck_a_p` equals `_2ga_p`; `_2g_cck_b_p` equals `_2gb_p`.
const CCK_A_P: [u8; TABLE] = OFDM_A_P;
const CCK_B_P: [u8; TABLE] = OFDM_B_P;
/// `rtw8822b_pwrtrk_5ga_p[0..3]` = `_5gb_p[0..3]` (every 5 GHz band row).
const P5: [u8; TABLE] = [
    0, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 9, 9, 10, 11, 12, 13, 14, 14, 15, 16, 17, 18, 19, 19, 20, 21,
    22, 22, 23,
];
/// `rtw8822b_pwrtrk_5ga_n[0..3]` = `_5gb_n[0..3]`.
const N5: [u8; TABLE] = [
    0, 1, 2, 2, 3, 4, 5, 5, 6, 7, 8, 8, 9, 10, 11, 11, 12, 13, 14, 14, 15, 16, 17, 17, 18, 19, 20,
    20, 21, 22,
];
/// `rtw8822b_hw_spec.iqk_threshold`.
const IQK_THRESHOLD: u8 = 8;
/// `rtw8822b_txagc_swing_offset` `max_tx_pwr_idx_offset`.
const MAX_OFFSET: u8 = 0xf;
/// `rtw8822b_hw_spec.max_power_index`.
const MAX_POWER_INDEX: u8 = 0x3f;

/// DESC_RATE 0x00..0x3f (`__RTW_RATE_SECTION_2SS_MAX`): legacy12, HT
/// MCS0..15, the unused HT3S/HT4S words and VHT1SS/2SS MCS0..9 a 2T2R B22
/// TXAGC program can write.
pub(super) const RATES: usize = 64;
/// `rtw_phy_config_swing_table` (positive, negative) for one path at one
/// DESC_RATE on the current channel: 5 GHz uses the `RTW_PWR_TRK_5G_*` rows
/// (identical for every band), 2.4 GHz the CCK tables for DESC_RATE 0..3.
fn swing(rate: u8, path: usize, band5: bool) -> (&'static [u8; TABLE], &'static [u8; TABLE]) {
    if band5 {
        return (&P5, &N5);
    }
    match (rate <= 3, path) {
        (true, 0) => (&CCK_A_P, &N),
        (true, _) => (&CCK_B_P, &N),
        (false, 0) => (&OFDM_A_P, &N),
        (false, _) => (&OFDM_B_P, &N),
    }
}

/// `rtw8822b_txagc_swing_offset`: (TXAGC index, swing index).
pub(super) fn swing_offset(delta: i8, offset: u8, default_ofdm_index: u8) -> (u8, u8) {
    let upper = default_ofdm_index.saturating_add(10);
    let offset = offset.min(MAX_OFFSET);
    let (agc, swing) = if delta >= 0 {
        let delta = delta as u8;
        if delta <= offset {
            (delta, default_ofdm_index)
        } else {
            (offset, (default_ofdm_index + delta - offset).min(upper))
        }
    } else {
        // default > |delta| ? default + delta : swing_lower_bound (0).
        (0, default_ofdm_index.saturating_sub(delta.unsigned_abs()))
    };
    (agc, swing.min(radio8822b::TXSCALE.len() as u8 - 1))
}

/// Outcome of one `rtw8822b_pwr_track` watchdog pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Pass {
    /// RF42[17:16] conversion triggered; sample on the next pass.
    Triggered,
    /// Meter sampled; `iqk` reports `rtw_phy_pwrtrack_need_iqk`.
    Tracked { thermal: u8, iqk: bool },
    /// The current rate was never written by the committed program; no
    /// register access, no state change.
    Skipped,
}

/// Per-owner `rtw_dm_info` power-tracking state.
#[derive(Clone, Copy, Debug)]
pub(super) struct Tracker {
    efuse: u8,
    default_ofdm_index: u8,
    avg: Ewma,
    thermal_avg: u8,
    thermal_k: u8,
    delta: [i8; 2],
    triggered: bool,
    init_trigger: bool,
}
impl Tracker {
    /// `rtw8822b_pwrtrack_init` state: `efuse.thermal_meter[RF_PATH_A]`
    /// (0xff = erased, tracking disabled), `default_ofdm_index` from the PHY
    /// tail, `thermal_meter_k` from EFUSE and `pwr_trk_init_trigger` set.
    pub(super) fn new(efuse: u8, default_ofdm_index: u8) -> Self {
        Self {
            efuse,
            default_ofdm_index,
            avg: Ewma::default(),
            thermal_avg: 0,
            thermal_k: efuse,
            delta: [0; 2],
            triggered: false,
            init_trigger: true,
        }
    }
    pub(super) fn delta_power(&self) -> [i8; 2] {
        self.delta
    }
    /// `rtw8822b_pwr_track` for the current `dm_info->tx_rate` (DESC_RATE)
    /// on the committed channel (`Authority::b22_channel`). `indices` are the committed program's
    /// per-path coded TXAGC indices for DESC_RATE 0..`indices.1` (legacy12,
    /// plus the bound HT20/HT40 MCS0..15 or VHT80 words,
    /// [`super::power_policy::Gate::b22_rate_indices`]) and `temperature` the
    /// `N2BP` thermal-window check.
    pub(super) async fn pass(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        indices: ([[u8; RATES]; 2], usize),
        temperature: impl Fn(u8) -> Result<(), Error>,
        limits: Limits,
        tx_rate: u8,
    ) -> Result<Pass, Error> {
        // rtw8822b_phy_pwrtrack: an erased thermal meter disables tracking;
        // refused here before any write.
        let (indices, count) = indices;
        if self.efuse == 0xff {
            return Err(Error::Unsupported);
        }
        // A rate the committed program never wrote has no index to offset
        // from: skip the pass (no RF42 trigger, no state change).
        let rate = usize::from(tx_rate);
        if rate >= count.min(RATES) || indices.iter().all(|path| path[rate] == 0) {
            return Ok(Pass::Skipped);
        }
        let band5 = super::band5::primary(auth.b22_channel().ok_or(Error::State)?);
        if !self.triggered {
            enclosed(|op| auth.run(op), radio8822b::rf(io, 0, 0x42, 3 << 16, 3)).await?;
            self.triggered = true;
            return Ok(Pass::Triggered);
        }
        self.triggered = false;
        let thermal = enclosed(|op| auth.run(op), async {
            let t = ((radio8822b::rf_read(io, 0, 0x42).await? & 0xfc00) >> 10) as u8;
            if !(limits.thermal[0]..=limits.thermal[1]).contains(&t) {
                return Err(Error::Prerequisite);
            }
            temperature(t)?;
            Ok(t)
        })
        .await?;
        self.avg.add(thermal, 2);
        self.thermal_avg = self.avg.read();
        let changed = self.thermal_avg != thermal;
        if self.init_trigger || changed {
            self.init_trigger = false;
            // 8822B has one thermal meter (path A) for both paths.
            let delta = self.thermal_avg.abs_diff(self.efuse).min(TABLE as u8 - 1);
            for path in 0..2 {
                let (p, n) = swing(tx_rate, path, band5);
                let current = if self.thermal_avg > self.efuse {
                    p[usize::from(delta)] as i8
                } else {
                    -(n[usize::from(delta)] as i8)
                };
                if current > limits.up as i8 || current < -(limits.down as i8) {
                    return Err(Error::Prerequisite);
                }
                if current == self.delta[path] {
                    continue;
                }
                self.delta[path] = current;
                let index = indices[path][usize::from(tx_rate)].min(MAX_POWER_INDEX);
                let (agc, swing) =
                    swing_offset(current, MAX_POWER_INDEX - index, self.default_ofdm_index);
                let (agc_reg, scale_reg) = REGS[path];
                enclosed(|op| auth.run(op), async {
                    super::radio::mask(io, agc_reg, AGC, u32::from(agc)).await?;
                    super::radio::mask(
                        io,
                        scale_reg,
                        SCALE,
                        radio8822b::TXSCALE[usize::from(swing)],
                    )
                    .await
                })
                .await?;
            }
        }
        let iqk = self.thermal_avg.abs_diff(self.thermal_k) >= IQK_THRESHOLD;
        if iqk {
            self.thermal_k = self.thermal_avg;
        }
        Ok(Pass::Tracked { thermal, iqk })
    }
}

/// `rtw8822b_pwrtrack_set_pwr` (TXAGC index, TX scale) registers per path.
const REGS: [(u16, u16); 2] = [(0xc94, 0xc1c), (0xe94, 0xe1c)];
/// `GENMASK(29, 25)` of 0xc94/0xe94.
const AGC: u32 = 0x3e00_0000;
/// `GENMASK(31, 21)` of 0xc1c/0xe1c.
const SCALE: u32 = 0xffe0_0000;

/// The TXAGC-index/TX-scale fields of both paths as the base program left
/// them (read at dm init), restored when tracking stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Base([[u32; 2]; 2]);
impl Base {
    pub(super) async fn capture(io: &mut impl Io) -> Result<Self, Error> {
        let mut v = [[0; 2]; 2];
        for (path, (agc, scale)) in REGS.into_iter().enumerate() {
            v[path] = [
                super::radio::read(io, agc).await? & AGC,
                super::radio::read(io, scale).await? & SCALE,
            ];
        }
        Ok(Self(v))
    }
    pub(super) async fn restore(&self, io: &mut impl Io) -> Result<(), Error> {
        for (path, (agc, scale)) in REGS.into_iter().enumerate() {
            super::radio::mask(io, agc, AGC, self.0[path][0] >> AGC.trailing_zeros()).await?;
            super::radio::mask(io, scale, SCALE, self.0[path][1] >> SCALE.trailing_zeros()).await?;
        }
        Ok(())
    }
}
