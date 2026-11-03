// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8822BE ("B22") thermal power tracking: Linux 7.3-rc4
//! `rtw8822b.c::rtw8822b_pwr_track` (`power_track_type` 0) over
//! `rtw8822b_phy_pwrtrack`, `_pwrtrack_path`, `_pwrtrack_set`,
//! `_pwrtrack_set_pwr` and `_txagc_swing_offset`, with the `phy.c`
//! helpers `rtw_phy_config_swing_table` (2.4 GHz), `rtw_phy_pwrtrack_avg`
//! (`DECLARE_EWMA(thermal, 10, 4)`), `_thermal_changed`, `_get_delta`,
//! `_get_pwridx` and `_need_iqk` (`iqk_threshold` 8) and the
//! `rtw8822b_pwr_track_type0_tbl` 2.4 GHz rows.
//!
//! `rtw_phy_get_tx_power_index` is replaced by the signed `N2BP` per-path,
//! per-rate coded index (the actually programmed TXAGC); a rate outside the
//! measured legacy set is refused rather than derived. Every register access
//! runs inside the `N2BP` (and `N2BQ`) source invocations and current policy;
//! a meter sample outside the measured thermal windows is refused. When
//! `_need_iqk` fires, the caller must run `rtw8822b_do_iqk` under its own
//! qualified record; this module never issues IQK.
use super::{
    dm::Ewma,
    firmware_transport::{enclosed, Error, Io},
    operating8822b, radio8822b,
};
use narf_wireless::reg::RegulatoryDomain;

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
/// `rtw8822b_hw_spec.iqk_threshold`.
const IQK_THRESHOLD: u8 = 8;
/// `rtw8822b_txagc_swing_offset` `max_tx_pwr_idx_offset`.
const MAX_OFFSET: u8 = 0xf;
/// `rtw8822b_hw_spec.max_power_index`.
const MAX_POWER_INDEX: u8 = 0x3f;

/// `rtw_phy_config_swing_table` 2.4 GHz rows: (positive, negative) for one
/// path at one DESC_RATE (CCK rates 0..3 use the CCK tables).
fn swing(rate: u8, path: usize) -> (&'static [u8; TABLE], &'static [u8; TABLE]) {
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
    /// `rtw8822b_pwr_track` for the current `dm_info->tx_rate` (DESC_RATE).
    pub(super) async fn pass(
        &mut self,
        io: &mut impl Io,
        power: &operating8822b::Envelope,
        policy: &impl Fn() -> Result<RegulatoryDomain, Error>,
        tx_rate: u8,
    ) -> Result<Pass, Error> {
        // rtw8822b_phy_pwrtrack: an erased thermal meter disables tracking;
        // refused here before any write.
        if self.efuse == 0xff || usize::from(tx_rate) >= operating8822b::LEGACY {
            return Err(Error::Unsupported);
        }
        if !self.triggered {
            enclosed(
                |op| power.invoke(policy, op),
                radio8822b::rf(io, 0, 0x42, 3 << 16, 3),
            )
            .await?;
            self.triggered = true;
            return Ok(Pass::Triggered);
        }
        self.triggered = false;
        let thermal = enclosed(|op| power.invoke(policy, op), async {
            let t = ((radio8822b::rf_read(io, 0, 0x42).await? & 0xfc00) >> 10) as u8;
            power.temperature(t)?;
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
                let (p, n) = swing(tx_rate, path);
                let current = if self.thermal_avg > self.efuse {
                    p[usize::from(delta)] as i8
                } else {
                    -(n[usize::from(delta)] as i8)
                };
                if current == self.delta[path] {
                    continue;
                }
                self.delta[path] = current;
                let index = power.indices()[path][usize::from(tx_rate)].min(MAX_POWER_INDEX);
                let (agc, swing) =
                    swing_offset(current, MAX_POWER_INDEX - index, self.default_ofdm_index);
                let (agc_reg, scale_reg) = if path == 0 {
                    (0xc94, 0xc1c)
                } else {
                    (0xe94, 0xe1c)
                };
                enclosed(|op| power.invoke(policy, op), async {
                    super::radio::mask(io, agc_reg, 0x3e00_0000, u32::from(agc)).await?;
                    super::radio::mask(
                        io,
                        scale_reg,
                        0xffe0_0000,
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
