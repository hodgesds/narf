// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE dynamic-mechanism pieces of the station watchdog.
//!
//! - [`rx_pwdb`] — `trx.c::_rtl92ee_query_rxphystatus` `rx_pwdb_all` (the
//!   value `rtl_process_pwdb` smooths into `undec_sm_pwdb`): OFDM
//!   `((cck_sig_qual_ofdm_pwdb_all >> 1) & 0x7f) - 110`; CCK the 8192EE
//!   LNA/VGA table with `rx_pwr_all += 16` (no 88EE post-table step) and the
//!   `!cck_highpwr` boost, both through `rtl_query_rxpwrpercentage`.
//! - [`ra_state`] — `dm.c::_rtl92ee_dm_ra_state_check` with
//!   `rtl92ee_dm_init_rate_adaptive_mask` thresholds (`high_rssi_thresh_for_ra`
//!   50, `low_rssi_thresh_for_ra40m` 20, `go_up_gap` 5 raising high from
//!   MIDDLE and both from LOW).
//!
//! Watchdog order (`rtl92ee_dm_watchdog`, only with `rfpwr_state == ERFON`,
//! firmware out of power save and awake): common info, false-alarm
//! statistics, RSSI monitor, DIG, adaptivity, CCK PD, **RA mask refresh**,
//! EDCA turbo, ATC switch, primary CCA. This profile composes the RA mask
//! refresh; the other steps are not run (their registers keep the
//! `rtl92ee_hw_init` table values). `rtl92ee_dm_init_txpower_tracking` only
//! seeds software indices: the 8192EE watchdog has no TX-power tracking step.

use super::super::rate_adaptive::{rx_power_percentage, STA_HIGH, STA_LOW, STA_MIDDLE};

/// `p_ra->high_rssi_thresh_for_ra` / `low_rssi_thresh_for_ra40m`.
pub const HIGH_RSSI_THRESH_FOR_RA: i64 = 50;
pub const LOW_RSSI_THRESH_FOR_RA40M: i64 = 20;
const GO_UP_GAP: i64 = 5;

/// `_rtl92ee_dm_ra_state_check`: the new `ratr_state` for `rssi` when it
/// differs from `current`. The state is passed unchanged as
/// `rtl92ee_update_hal_rate_mask`'s `rssi_level` (1 HIGH, 2 MIDDLE, LOW and
/// INIT the full mask).
pub fn ra_state(rssi: i64, current: u8) -> Option<u8> {
    let (mut high, mut low) = (HIGH_RSSI_THRESH_FOR_RA, LOW_RSSI_THRESH_FOR_RA40M);
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

/// `_rtl92ee_query_rxphystatus` `rx_pwdb_all` from the PHY status
/// (`struct phy_status_rpt`: byte 4 `cck_sig_qual_ofdm_pwdb_all`, byte 5
/// `cck_agc_rpt_ofdm_cfosho_a`). `cck_highpwr` is BB `0x824` BIT(9)
/// (`rtlphy->cck_high_power`).
pub fn rx_pwdb(phy: &[u8], cck: bool, cck_highpwr: bool) -> Option<u8> {
    if phy.len() < 6 {
        return None;
    }
    if !cck {
        return Some(rx_power_percentage(i32::from((phy[4] >> 1) & 0x7f) - 110));
    }
    let agc = phy[5];
    let vga = i32::from(agc & 0x1f);
    let mut power = match (agc & 0xe0) >> 5 {
        7 if vga <= 27 => -100 + 2 * (27 - vga),
        7 => -100,
        6 => -48 + 2 * (2 - vga),
        5 => -42 + 2 * (7 - vga),
        4 => -36 + 2 * (7 - vga),
        3 => -24 + 2 * (7 - vga),
        2 if cck_highpwr => -12 + 2 * (5 - vga),
        2 => -6 + 2 * (5 - vga),
        1 => 8 - 2 * vga,
        _ => 14 - 2 * vga,
    };
    // `s8 rx_pwr_all`: every table value plus 16 stays inside i8.
    power += 16;
    let mut pwdb = rx_power_percentage(power);
    if !cck_highpwr {
        if pwdb >= 80 {
            pwdb = ((pwdb - 80) << 1) + ((pwdb - 80) >> 1) + 80;
        } else if (20..=78).contains(&pwdb) {
            pwdb += 3;
        }
        pwdb = pwdb.min(100);
    }
    Some(pwdb)
}
