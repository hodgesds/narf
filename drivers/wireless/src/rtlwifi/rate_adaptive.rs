// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EE driver-controlled rate adaptation (Linux v7.2 rtlwifi
//! `useramask`, `dm_type == DM_TYPE_BYDRIVER`).
//!
//! * RX PWDB: `rtl8188ee/trx.c::_rtl88ee_query_rxphystatus` (CCK LNA/VGA
//!   table and OFDM `pwdb_all`) with `stats.c::rtl_query_rxpwrpercentage`.
//! * Smoothing: `stats.c::rtl_process_phyinfo` → `rtl_process_pwdb`
//!   (`RX_SMOOTH_FACTOR` 20, +1 on a rising sample), only for frames whose
//!   BSSID matches (`_rtl88ee_translate_rx_signal_stuff`).
//! * Level: `rtl8188ee/dm.c::rtl88e_dm_refresh_rate_adaptive_mask`
//!   (DM_RATR_STA_HIGH/MIDDLE/LOW with 50/20, 55/20, 50/25 hysteresis).
//! * Mask: `rtl8188ee/hw.c::rtl88ee_update_hal_rate_mask` (1T1R, HT20,
//!   station MACID 0) sent as `H2C_88E_RA_MASK` (0x84, 5 bytes).

/// `fw.h` `H2C_88E_RA_MASK`: the entry after `H2C_88E_AOAC_RSVDPAGE` (0x83).
pub(super) const H2C_RA_MASK: u8 = 0x84;
/// `stats.h` `RX_SMOOTH_FACTOR`.
const RX_SMOOTH_FACTOR: i64 = 20;
/// `wifi.h` `RATR_INX_WIRELESS_*`.
pub(super) const RATR_INX_NGB: u8 = 0;
pub(super) const RATR_INX_GB: u8 = 4;
pub(super) const RATR_INX_B: u8 = 6;
/// `rtl8188ee/dm.h` `DM_RATR_STA_*`.
pub(super) const STA_INIT: u8 = 0;
pub(super) const STA_HIGH: u8 = 1;
pub(super) const STA_MIDDLE: u8 = 2;
pub(super) const STA_LOW: u8 = 3;

/// `rtl_query_rxpwrpercentage`.
pub(super) fn rx_power_percentage(power: i32) -> u8 {
    if power <= -100 || power >= 20 {
        0
    } else if power >= 0 {
        100
    } else {
        (100 + power) as u8
    }
}

/// `_rtl88ee_query_rxphystatus` `rx_pwdb_all` for one 28-byte EE PHY
/// status (`rx_fwinfo_88e` / `phy_sts_cck_8192s_t`). `cck_highpwr` is BB
/// `RFPGA0_XA_HSSIPARAMETER2` (0x824) BIT(9) read while RF is on.
pub(super) fn rx_pwdb(phy: &[u8; 28], cck: bool, cck_highpwr: bool) -> u8 {
    if !cck {
        // OFDM/HT: rx_pwr_all = ((pwdb_all >> 1) & 0x7f) - 110.
        return rx_power_percentage(i32::from((phy[4] >> 1) & 0x7f) - 110);
    }
    // cck_agc_rpt follows adc_pwdb_X[4] and sq_rpt.
    let agc = phy[5];
    let lna = (agc & 0xe0) >> 5;
    let vga = i32::from(agc & 0x1f);
    let mut power = match lna {
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
    power += 6;
    // CCK gain is smaller than OFDM/MCS gain: add 6 by experience.
    let mut pwdb = (rx_power_percentage(power) + 6).min(100);
    pwdb = match pwdb {
        35..=42 => pwdb - 2,
        27..=34 => pwdb - 6,
        15..=26 => pwdb - 8,
        5..=14 => pwdb - 4,
        _ => pwdb,
    };
    if !cck_highpwr {
        if pwdb >= 80 {
            pwdb = (((pwdb - 80) << 1) + ((pwdb - 80) >> 1) + 80).min(100);
        } else if (20..=78).contains(&pwdb) {
            pwdb += 3;
        }
    }
    pwdb
}

/// `_rtl88ee_translate_rx_signal_stuff` `packet_matchbssid` for an
/// already admitted (no CRC/ICV/HW error) MPDU: not a control frame and
/// the ToDS/FromDS-selected BSSID address equals `bssid`.
pub(super) fn matches_bssid(bytes: &[u8], bssid: [u8; 6]) -> bool {
    if bytes.len() < 24 || bytes[0] & 0x0c == 0x04 {
        return false;
    }
    let at = match bytes[1] & 3 {
        1 => 4,  // ToDS: addr1
        2 => 10, // FromDS: addr2
        _ => 16, // addr3
    };
    bytes[at..at + 6] == bssid
}

/// Station-mode `rtlpriv->dm.undec_sm_pwdb` and `rtlpriv->ra` state.
#[derive(Debug, Clone, Copy)]
pub(super) struct State {
    /// `dm.undec_sm_pwdb`: zero-initialised (kzalloc) on RTL8188EE.
    smoothed: i64,
    /// `ra.pre_ratr_state`.
    previous: u8,
    /// Last watchdog refresh (`RTL_WATCHDOG_TIME`).
    last_ms: Option<u64>,
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    /// `rtl88e_dm_init_rate_adaptive_mask`: both states INIT.
    pub(super) const fn new() -> Self {
        Self {
            smoothed: 0,
            previous: STA_INIT,
            last_ms: None,
        }
    }
    pub(super) fn smoothed(&self) -> i64 {
        self.smoothed
    }
    pub(super) fn level(&self) -> u8 {
        self.previous
    }
    /// `rtl_process_pwdb` (station: no per-sta entry).
    pub(super) fn sample(&mut self, pwdb: u8) {
        let mut value = self.smoothed;
        if value < 0 {
            value = i64::from(pwdb);
        }
        let rising = i64::from(pwdb) > value;
        value = (value * (RX_SMOOTH_FACTOR - 1) + i64::from(pwdb)) / RX_SMOOTH_FACTOR;
        if rising {
            value += 1;
        }
        self.smoothed = value;
    }
    /// `rtl88e_dm_refresh_rate_adaptive_mask` hysteresis. Returns the new
    /// level when it differs from `pre_ratr_state` (the caller must then
    /// install the mask before `commit`).
    pub(super) fn refresh(&self) -> Option<u8> {
        let (high, low) = match self.previous {
            STA_MIDDLE => (55, 20),
            STA_LOW => (50, 25),
            _ => (50, 20),
        };
        let state = if self.smoothed > high {
            STA_HIGH
        } else if self.smoothed > low {
            STA_MIDDLE
        } else {
            STA_LOW
        };
        (state != self.previous).then_some(state)
    }
    /// `p_ra->pre_ratr_state = p_ra->ratr_state` after the update.
    pub(super) fn commit(&mut self, level: u8) {
        self.previous = level;
    }
    /// The 2 s `rtl_watchdog_wq_callback` period gate.
    pub(super) fn due(&mut self, now: u64) -> bool {
        if self
            .last_ms
            .is_some_and(|last| now.saturating_sub(last) < 2_000)
        {
            return false;
        }
        self.last_ms = Some(now);
        true
    }
}

/// `rtl88ee_update_hal_rate_mask` for the RTL8188EE (RF_1T1R) station at
/// HT20 with MACID 0. `legacy` is `supp_rates[0]` (bit order 1, 2, 5.5,
/// 11, 6 … 54 Mbps), `mcs` is `ht_cap.mcs.rx_mask[0]` (None: not HT).
/// Returns the 5-byte H2C payload: `(ratr_bitmap & 0x0fffffff) |
/// ratr_index << 28` little-endian, then `macid | SGI<<5 | 0x80`.
pub(super) fn rate_mask(legacy: u16, mcs: Option<u8>, level: u8, sgi: bool) -> [u8; 5] {
    let mut bitmap = u32::from(legacy & 0xfff);
    let index;
    let mut short = false;
    if let Some(mcs) = mcs {
        // WIRELESS_MODE_N_24G, 1T1R, curtxbw_40mhz = mac->bw_40 = 0.
        index = RATR_INX_NGB;
        bitmap |= u32::from(mcs) << 12;
        bitmap &= match level {
            STA_HIGH => 0x000f_0000,
            STA_MIDDLE => 0x000f_f000,
            _ => 0x000f_f005,
        };
        short = sgi;
    } else if legacy <= 0xf {
        // WIRELESS_MODE_B.
        index = RATR_INX_B;
        bitmap &= if bitmap & 0xc != 0 { 0xd } else { 0xf };
    } else {
        // WIRELESS_MODE_G.
        index = RATR_INX_GB;
        bitmap &= match level {
            STA_HIGH => 0x0f00,
            STA_MIDDLE => 0x0ff0,
            _ => 0x0ff5,
        };
    }
    let word = (bitmap & 0x0fff_ffff) | (u32::from(index) << 28);
    let bytes = word.to_le_bytes();
    [
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        if short { 0x20 } else { 0 } | 0x80,
    ]
}

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn phy(pwdb_all: u8, agc: u8) -> [u8; 28] {
        let mut phy = [0; 28];
        phy[4] = pwdb_all;
        phy[5] = agc;
        phy
    }

    pub(crate) fn smoke_rtl8188ee_rx_pwdb_and_smoothing_match_linux() -> TestResult {
        // rtl_query_rxpwrpercentage edges.
        if rx_power_percentage(-100) != 0
            || rx_power_percentage(20) != 0
            || rx_power_percentage(0) != 100
            || rx_power_percentage(-40) != 60
        {
            return TestResult::Fail("rxpwrpercentage differs from stats.c");
        }
        // OFDM: pwdb_all 0x8c -> ((0x8c>>1)&0x7f)-110 = -40 -> 60.
        if rx_pwdb(&phy(0x8c, 0), false, false) != 60 {
            return TestResult::Fail("OFDM PWDB differs from _rtl88ee_query_rxphystatus");
        }
        // CCK hand-computed Linux values: (agc, highpwr, pwdb).
        for (agc, high, expected) in [
            // LNA3 VGA7: -24+6 = -18 -> 82+6 = 88 -> !high: 8<<1+4+80 = 100.
            ((3 << 5) | 7, false, 100),
            // LNA7 VGA27: -100+6 = -94 -> 6+6 = 12 -> -4 = 8.
            ((7 << 5) | 27, false, 8),
            // LNA7 VGA30 (>27): -100+6 -> 12 -> 8.
            ((7 << 5) | 30, true, 8),
            // LNA2 VGA5 highpwr: -12+6 = -6 -> 94+6 = 100.
            ((2 << 5) | 5, true, 100),
            // LNA4 VGA7: -36+6 = -30 -> 70+6 = 76 -> +3 = 79.
            ((4 << 5) | 7, false, 79),
            // LNA5 VGA7: -42+6 = -36 -> 64+6 = 70, highpwr keeps 70.
            ((5 << 5) | 7, true, 70),
            // LNA6 VGA2: -48+6 = -42 -> 58+6 = 64 -> +3 = 67.
            ((6 << 5) | 2, false, 67),
            // LNA1 VGA31: 8-62+6 = -48 -> 52+6 = 58, high.
            ((1 << 5) | 31, true, 58),
            // LNA0 VGA31: 14-62+6 = -42 -> 64 high.
            (31, true, 64),
            // LNA7 VGA20: -86+6 = -80 -> 20+6 = 26 -> -8 = 18, high.
            ((7 << 5) | 20, true, 18),
            // LNA7 VGA16: -78+6 = -72 -> 28+6 = 34 -> -6 = 28 -> +3 = 31.
            ((7 << 5) | 16, false, 31),
            // LNA7 VGA12: -70+6 = -64 -> 36+6 = 42 -> -2 = 40, high.
            ((7 << 5) | 12, true, 40),
        ] {
            if rx_pwdb(&phy(0, agc), true, high) != expected {
                return TestResult::Fail("CCK PWDB differs from _rtl88ee_query_rxphystatus");
            }
        }
        // rtl_process_pwdb from the zeroed RTL8188EE state.
        let mut state = State::new();
        state.sample(60);
        if state.smoothed() != 4 {
            return TestResult::Fail("rising sample lacks the +1 of rtl_process_pwdb");
        }
        for _ in 0..200 {
            state.sample(60);
        }
        if !(59..=61).contains(&state.smoothed()) {
            return TestResult::Fail("smoothed PWDB did not converge");
        }
        let before = state.smoothed();
        state.sample(0);
        if state.smoothed() != before * 19 / 20 {
            return TestResult::Fail("falling sample differs from rtl_process_pwdb");
        }
        // BSSID selection by ToDS/FromDS; control frames never match.
        let bssid = [2, 0, 0, 0, 0, 1];
        let mut frame = [0u8; 24];
        frame[0] = 0x80;
        frame[16..22].copy_from_slice(&bssid);
        let mut from_ds = [0u8; 24];
        from_ds[0] = 0x08;
        from_ds[1] = 2;
        from_ds[10..16].copy_from_slice(&bssid);
        let mut control = frame;
        control[0] = 0xd4;
        if !matches_bssid(&frame, bssid)
            || !matches_bssid(&from_ds, bssid)
            || matches_bssid(&control, bssid)
            || matches_bssid(&frame[..20], bssid)
        {
            return TestResult::Fail("packet_matchbssid differs from Linux");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/rate",
        smoke_rtl8188ee_rx_pwdb_and_smoothing_match_linux
    );

    pub(crate) fn smoke_rtl8188ee_rate_mask_levels_match_linux() -> TestResult {
        // N_24G 1T1R HT20: all 12 legacy + MCS0-7.
        let cases = [
            (0xfff, Some(0xff), STA_INIT, [0x05, 0xf0, 0x0f, 0x00, 0x80]),
            (0xfff, Some(0xff), STA_HIGH, [0x00, 0x00, 0x0f, 0x00, 0x80]),
            (
                0xfff,
                Some(0xff),
                STA_MIDDLE,
                [0x00, 0xf0, 0x0f, 0x00, 0x80],
            ),
            (0xfff, Some(0xff), STA_LOW, [0x05, 0xf0, 0x0f, 0x00, 0x80]),
            // G: ratr_index 4.
            (0xfff, None, STA_INIT, [0xf5, 0x0f, 0x00, 0x40, 0x80]),
            (0xfff, None, STA_HIGH, [0x00, 0x0f, 0x00, 0x40, 0x80]),
            (0xfff, None, STA_MIDDLE, [0xf0, 0x0f, 0x00, 0x40, 0x80]),
            // B: ratr_index 6; 5.5/11 present -> & 0xd.
            (0xf, None, STA_HIGH, [0x0d, 0x00, 0x00, 0x60, 0x80]),
            (0x3, None, STA_LOW, [0x03, 0x00, 0x00, 0x60, 0x80]),
        ];
        for (legacy, mcs, level, expected) in cases {
            if rate_mask(legacy, mcs, level, false) != expected {
                return TestResult::Fail("RA mask differs from rtl88ee_update_hal_rate_mask");
            }
        }
        if rate_mask(0xfff, Some(0xff), STA_INIT, true)[4] != 0xa0 {
            return TestResult::Fail("SGI bit missing from the MACID byte");
        }
        // Hysteresis from INIT, then each state's own thresholds.
        let mut state = State::new();
        for _ in 0..300 {
            state.sample(52);
        }
        if state.refresh() != Some(STA_HIGH) {
            return TestResult::Fail("INIT 50/20 thresholds differ");
        }
        state.commit(STA_HIGH);
        if state.refresh().is_some() || state.level() != STA_HIGH {
            return TestResult::Fail("unchanged level was re-sent");
        }
        state.commit(STA_MIDDLE);
        if state.refresh().is_some() {
            return TestResult::Fail("MIDDLE did not use its 55 high threshold");
        }
        let mut low = State::new();
        for _ in 0..300 {
            low.sample(23);
        }
        low.commit(STA_LOW);
        if low.refresh().is_some() {
            return TestResult::Fail("LOW did not use its 25 low threshold");
        }
        low.commit(STA_HIGH);
        if low.refresh() != Some(STA_MIDDLE) {
            return TestResult::Fail("HIGH 50/20 thresholds differ");
        }
        // Watchdog period.
        let mut timer = State::new();
        if !timer.due(10) || timer.due(2009) || !timer.due(2010) {
            return TestResult::Fail("refresh period is not RTL_WATCHDOG_TIME");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/rate",
        smoke_rtl8188ee_rate_mask_levels_match_linux
    );
}
