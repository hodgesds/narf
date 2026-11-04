// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE dynamic-mechanism pieces of the station watchdog.
//!
//! - [`rx_pwdb`] — `trx.c::_rtl8723be_query_rxphystatus` `rx_pwdb_all` (the
//!   value `rtl_process_pwdb` smooths into `undec_sm_pwdb`): OFDM
//!   `((cck_sig_qual_ofdm_pwdb_all >> 1) & 0x7f) - 110`; CCK the 8723BE
//!   four-entry LNA table (`6 ⇒ -34`, `4 ⇒ -14`, `1 ⇒ 6`, `0 ⇒ 16`, each
//!   `- 2 * vga`; any other LNA index leaves `rx_pwr_all = 0`) through
//!   `rtl_query_rxpwrpercentage`, capped at 100. There is no `cck_highpwr`
//!   step: Linux reads BB `0x824` BIT(9) and discards it.
//! - [`ra_state`] — `dm.c::rtl8723be_dm_refresh_rate_adaptive_mask`: high
//!   `high_rssi_thresh_for_ra` (50), low `low2high_rssi_thresh_for_ra40m`,
//!   which `rtl8723be_dm_init_rate_adaptive_mask` never sets (it sets
//!   `low_rssi_thresh_for_ra40m`), so the zeroed `rtl_priv` gives 0;
//!   `go_up_gap` 5 raises high from MIDDLE and both from LOW. This is the
//!   RTL8821AE rule ([`super::super::rate_adaptive`]'s
//!   `refresh_rtl8821ae`), reproduced exactly.
//!
//! Watchdog order (`rtl8723be_dm_watchdog`, only with `rfpwr_state ==
//! ERFON`, firmware out of power save and awake, no RF change in progress):
//! common info, false-alarm statistics, RSSI monitor, DIG, dynamic EDCCA,
//! CCK PD, **RA mask refresh**, EDCA turbo, ATC switch, TX-power tracking,
//! dynamic TX power (empty in Linux). This profile composes the RA mask
//! refresh; the other steps are not run (their registers keep the
//! `rtl8723be_hw_init` table values).

use super::super::rate_adaptive::{rx_power_percentage, STA_HIGH, STA_LOW, STA_MIDDLE};

/// `p_ra->high_rssi_thresh_for_ra`.
pub const HIGH_RSSI_THRESH_FOR_RA: i64 = 50;
/// `p_ra->low2high_rssi_thresh_for_ra40m` (never initialised ⇒ 0).
pub const LOW2HIGH_RSSI_THRESH_FOR_RA40M: i64 = 0;
const GO_UP_GAP: i64 = 5;

/// `rtl8723be_dm_refresh_rate_adaptive_mask`: the new `ratr_state` for
/// `undec_sm_pwdb` when it differs from `pre_ratr_state`. The state is
/// passed unchanged as `rtl8723be_update_hal_rate_mask`'s `rssi_level`.
pub fn ra_state(rssi: i64, current: u8) -> Option<u8> {
    let (mut high, mut low) = (HIGH_RSSI_THRESH_FOR_RA, LOW2HIGH_RSSI_THRESH_FOR_RA40M);
    match current {
        STA_MIDDLE => high += GO_UP_GAP,
        STA_LOW => {
            high += GO_UP_GAP;
            low += GO_UP_GAP;
        }
        _ => {}
    }
    let state = if rssi > high {
        STA_HIGH
    } else if rssi > low {
        STA_MIDDLE
    } else {
        STA_LOW
    };
    (state != current).then_some(state)
}

/// `_rtl8723be_query_rxphystatus` `rx_pwdb_all` from the PHY status
/// (`struct phy_status_rpt`: byte 4 `cck_sig_qual_ofdm_pwdb_all`, byte 5
/// `cck_agc_rpt_ofdm_cfosho_a`).
pub fn rx_pwdb(phy: &[u8], cck: bool) -> Option<u8> {
    if phy.len() < 6 {
        return None;
    }
    if !cck {
        return Some(rx_power_percentage(i32::from((phy[4] >> 1) & 0x7f) - 110));
    }
    let agc = phy[5];
    let vga = i32::from(agc & 0x1f);
    let power = match (agc & 0xe0) >> 5 {
        6 => -34 - 2 * vga,
        4 => -14 - 2 * vga,
        1 => 6 - 2 * vga,
        0 => 16 - 2 * vga,
        _ => 0,
    };
    Some(rx_power_percentage(power).min(100))
}
