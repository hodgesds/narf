// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8188EU host rate adaptation, ported from Linux `rtl8xxxu/8188e.c`
//! (`rtl8188e_rate_decision`, `rtl8188e_handle_ra_tx_report2`,
//! `rtl8188e_arfb_refresh`, power training) and the station-side RSSI
//! plumbing of `rtl8xxxu/core.c` (`rtl8723au_rx_parse_phystats`,
//! `rtl8188e_cck_rssi`, `DECLARE_EWMA(rssi, 10, 16)`,
//! `rtl8xxxu_refresh_rate_mask`). Pure host state: no device access.

const RATESIZE: usize = 28;
const DESC_RATE_11M: u8 = 3;
const DESC_RATE_48M: u8 = 10;
const DESC_RATE_54M: u8 = 11;
const DESC_RATE_MCS5: u8 = 17;
const DESC_RATE_MCS7: u8 = 19;
const DESC_RATE_MCS13: u8 = 25;

const RETRY_PENALTY: [[u8; 6]; 23] = [
    [5, 4, 3, 2, 0, 3],
    [6, 5, 4, 3, 0, 4],
    [6, 5, 4, 2, 0, 4],
    [8, 7, 6, 4, 0, 6],
    [10, 9, 8, 6, 0, 8],
    [10, 9, 8, 4, 0, 8],
    [10, 9, 8, 2, 0, 8],
    [10, 9, 8, 0, 0, 8],
    [18, 17, 16, 8, 0, 16],
    [26, 25, 24, 16, 0, 24],
    [34, 33, 32, 24, 0, 32],
    [34, 31, 28, 20, 0, 32],
    [34, 31, 27, 18, 0, 32],
    [34, 31, 26, 16, 0, 32],
    [34, 30, 22, 16, 0, 32],
    [34, 30, 24, 16, 0, 32],
    [49, 46, 40, 16, 0, 48],
    [49, 45, 32, 0, 0, 48],
    [49, 45, 22, 18, 0, 48],
    [49, 40, 24, 16, 0, 48],
    [49, 32, 18, 12, 0, 48],
    [49, 22, 18, 14, 0, 48],
    [49, 16, 16, 0, 0, 48],
];
const PT_PENALTY: [u8; 6] = [34, 31, 30, 24, 0, 32];
/// `retry_penalty_idx_normal` (RSSI>TH, RSSI<TH). Cut I chips are refused
/// by `rtl8188eu_identify_chip`, so the cut-I tables are never selected.
const RETRY_PENALTY_IDX: [[u8; RATESIZE]; 2] = [
    [
        4, 4, 4, 5, 4, 4, 5, 7, 7, 7, 8, 0x0a, 4, 4, 4, 4, 6, 0x0a, 0x0b, 0x0d, 5, 5, 7, 7, 8,
        0x0b, 0x0d, 0x0f,
    ],
    [
        0x0a, 0x0a, 0x0b, 0x0c, 0x0a, 0x0a, 0x0b, 0x0c, 0x0d, 0x10, 0x13, 0x13, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f, 0x11, 0x13, 0x13, 9, 9, 9, 9, 0x0c, 0x0e, 0x11, 0x13,
    ],
];
const RETRY_PENALTY_UP_IDX: [u8; RATESIZE] = [
    0x0c, 0x0d, 0x0d, 0x0f, 0x0d, 0x0e, 0x0f, 0x0f, 0x10, 0x12, 0x13, 0x14, 0x0f, 0x10, 0x10, 0x12,
    0x12, 0x13, 0x14, 0x15, 0x11, 0x11, 0x12, 0x13, 0x13, 0x13, 0x14, 0x15,
];
const RSSI_THRESHOLD: [u8; RATESIZE] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0x24, 0x26, 0x2a, 0x18, 0x1a, 0x1d, 0x1f, 0x21, 0x27, 0x29, 0x2a, 0,
    0, 0, 0x1f, 0x23, 0x28, 0x2a, 0x2c,
];
const N_THRESHOLD_HIGH: [u16; RATESIZE] = [
    4, 4, 8, 16, 24, 36, 48, 72, 96, 144, 192, 216, 60, 80, 100, 160, 240, 400, 600, 800, 300, 320,
    480, 720, 1000, 1200, 1600, 2000,
];
const N_THRESHOLD_LOW: [u16; RATESIZE] = [
    2, 2, 4, 8, 12, 18, 24, 36, 48, 72, 96, 108, 30, 40, 50, 80, 120, 200, 300, 400, 150, 160, 240,
    360, 500, 600, 800, 1000,
];
const DROPPING_NECESSARY: [u8; RATESIZE] = [
    1, 1, 1, 1, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 5, 6, 7, 8, 9, 10, 11, 12,
];
const PENDING_FOR_RATE_UP_FAIL: [u8; 5] = [2, 10, 24, 40, 60];
/// `dynamic_tx_rpt_timing`: REG_TX_REPORT_TIME values for 200..1200 ms.
pub(super) const DYNAMIC_TX_RPT_TIMING: [u16; 6] = [0x186a, 0x30d4, 0x493e, 0x61a8, 0x7a12, 0x927c];
/// `TX_RPT2_ITEM_SIZE`.
const TX_RPT2_ITEM_SIZE: usize = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Timing {
    Default,
    Increase,
    Decrease,
}

/// `struct rtl8xxxu_ra_info` for the single station MACID 0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateAdaptation {
    pub(super) decision_rate: u8,
    pre_rate: u8,
    highest_rate: u8,
    lowest_rate: u8,
    rate_mask: u32,
    ra_use_rate: u32,
    rssi_sta_ra: u8,
    pre_rssi_sta_ra: u8,
    sgi_enable: bool,
    pub(super) rate_sgi: bool,
    nsc_up: u32,
    nsc_down: u32,
    pub(super) rpt_time: u16,
    pre_min_rpt_time: u16,
    retry: [u16; 5],
    drop: u16,
    total: u32,
    ra_waiting_counter: u8,
    ra_pending_counter: u8,
    ra_drop_after_down: u8,
    dynamic_tx_rpt_timing_counter: u8,
    ra_stage: u8,
    pt_try_state: u8,
    pub(super) pt_stage: u8,
    pt_smooth_factor: u8,
    pt_stop_count: u8,
    pt_pre_rate: u8,
    pt_pre_rssi: u8,
    pt_mode_ss: u8,
}

impl Default for RateAdaptation {
    fn default() -> Self {
        Self::new()
    }
}

impl RateAdaptation {
    /// `rtl8188e_ra_info_init_all`.
    pub const fn new() -> Self {
        let mid = (N_THRESHOLD_HIGH[DESC_RATE_MCS7 as usize] as u32
            + N_THRESHOLD_LOW[DESC_RATE_MCS7 as usize] as u32)
            / 2;
        Self {
            decision_rate: DESC_RATE_MCS7,
            pre_rate: DESC_RATE_MCS7,
            highest_rate: DESC_RATE_MCS7,
            lowest_rate: 0,
            rate_mask: 0xfffff,
            ra_use_rate: 0xfffff,
            rssi_sta_ra: 0,
            pre_rssi_sta_ra: 0,
            sgi_enable: false,
            rate_sgi: false,
            nsc_up: mid,
            nsc_down: mid,
            rpt_time: 0x927c,
            pre_min_rpt_time: 0,
            retry: [0; 5],
            drop: 0,
            total: 0,
            ra_waiting_counter: 0,
            ra_pending_counter: 0,
            ra_drop_after_down: 0,
            dynamic_tx_rpt_timing_counter: 0,
            ra_stage: 0,
            pt_try_state: 0,
            pt_stage: 5,
            pt_smooth_factor: 192,
            pt_stop_count: 0,
            pt_pre_rate: 0,
            pt_pre_rssi: 0,
            pt_mode_ss: 0,
        }
    }
    /// `rtl8188e_update_rate_mask` -> `rtl8188e_arfb_refresh`.
    pub fn update_rate_mask(&mut self, mask: u32, sgi: bool) {
        self.rate_mask = mask;
        self.sgi_enable = sgi;
        self.ra_use_rate = mask;
        // Linux scans BIT(28)..BIT(0); bit 28 is outside RATESIZE.
        self.highest_rate = (0..=RATESIZE as u8)
            .rev()
            .find(|i| mask & (1 << i) != 0)
            .unwrap_or(0);
        self.lowest_rate = (0..RATESIZE as u8)
            .find(|i| mask & (1 << i) != 0)
            .unwrap_or(0);
        self.pt_mode_ss = if self.highest_rate > DESC_RATE_MCS7 {
            3
        } else if self.highest_rate > DESC_RATE_54M {
            2
        } else if self.highest_rate > DESC_RATE_11M {
            1
        } else {
            0
        };
    }
    /// `rtl8188e_ra_set_rssi` (`report_rssi`): an SNR percentage.
    pub fn set_rssi(&mut self, rssi: u8) {
        self.rssi_sta_ra = rssi;
    }
    pub fn mask(&self) -> u32 {
        self.rate_mask
    }
    /// The DATA rate `rtl8xxxu_fill_txdesc_v3` writes: `decision_rate`.
    /// `rtl8188e_ra_info_init_all` starts at MCS7 before any mask exists;
    /// rate_decision itself treats `pre_rate > highest_rate` as
    /// `highest_rate`, and this clamp applies the same bound at TX so a
    /// legacy peer never receives an MCS before the first report.
    pub fn tx_rate(&self) -> u8 {
        if self.ra_use_rate & (1 << self.decision_rate) != 0 {
            self.decision_rate
        } else {
            self.highest_rate
        }
    }
    fn set_tx_rpt_timing(&mut self, timing: Timing) {
        let mut idx = (0..5)
            .find(|&i| DYNAMIC_TX_RPT_TIMING[i] == self.rpt_time)
            .unwrap_or(5);
        match timing {
            Timing::Default => idx = 0,
            Timing::Increase => {
                if idx < 5 {
                    idx += 1;
                }
            }
            Timing::Decrease => idx = idx.saturating_sub(1),
        }
        self.rpt_time = DYNAMIC_TX_RPT_TIMING[idx];
    }
    fn rate_down(&mut self) {
        let mut rate_id = self.pre_rate;
        if rate_id > self.highest_rate {
            rate_id = self.highest_rate;
        } else if self.rate_sgi {
            self.rate_sgi = false;
        } else if rate_id > self.lowest_rate {
            if let Some(i) = (self.lowest_rate..rate_id)
                .rev()
                .find(|i| self.ra_use_rate & (1 << i) != 0)
            {
                rate_id = i;
            }
        } else {
            rate_id = self.lowest_rate;
        }
        if self.ra_waiting_counter == 1 {
            self.ra_waiting_counter += 1;
            self.ra_pending_counter += 1;
        } else if self.ra_waiting_counter > 1 {
            self.ra_waiting_counter = 0;
            self.ra_pending_counter = 0;
        }
        self.ra_pending_counter = self.ra_pending_counter.min(4);
        self.ra_drop_after_down = 1;
        self.decision_rate = rate_id;
        self.set_tx_rpt_timing(Timing::Decrease);
    }
    fn rate_up(&mut self) {
        let mut rate_id = self.pre_rate;
        let mut finish = false;
        if self.ra_waiting_counter == 1 {
            self.ra_waiting_counter = 0;
            self.ra_pending_counter = 0;
        } else if self.ra_waiting_counter > 1 {
            self.pre_rssi_sta_ra = self.rssi_sta_ra;
            finish = true;
        }
        if !finish {
            self.set_tx_rpt_timing(Timing::Default);
            if rate_id < self.highest_rate {
                if let Some(i) =
                    (rate_id + 1..=self.highest_rate).find(|i| self.ra_use_rate & (1 << i) != 0)
                {
                    rate_id = i;
                }
            } else if rate_id == self.highest_rate {
                if self.sgi_enable && !self.rate_sgi {
                    self.rate_sgi = true;
                } else if !self.sgi_enable {
                    self.rate_sgi = false;
                }
            } else {
                rate_id = self.highest_rate;
            }
        }
        if self.ra_waiting_counter
            == 4 + PENDING_FOR_RATE_UP_FAIL[usize::from(self.ra_pending_counter)]
        {
            self.ra_waiting_counter = 0;
        } else {
            self.ra_waiting_counter += 1;
        }
        self.decision_rate = rate_id;
    }
    fn reset_ra_counter(&mut self) {
        let r = usize::from(self.decision_rate);
        let mid = (u32::from(N_THRESHOLD_HIGH[r]) + u32::from(N_THRESHOLD_LOW[r])) >> 1;
        self.nsc_up = mid;
        self.nsc_down = mid;
    }
    /// `rtl8188e_rate_decision`.
    fn rate_decision(&mut self) {
        if self.total == 0 {
            return;
        }
        if self.ra_drop_after_down != 0 {
            self.ra_drop_after_down -= 1;
            self.reset_ra_counter();
            return;
        }
        // Linux compares in int arithmetic after integer promotion.
        let rssi = i32::from(self.rssi_sta_ra);
        let pre = i32::from(self.pre_rssi_sta_ra);
        if rssi < pre - 3 || rssi > pre + 3 {
            self.pre_rssi_sta_ra = self.rssi_sta_ra;
            self.ra_waiting_counter = 0;
            self.ra_pending_counter = 0;
        }
        let rate_id = usize::from(self.pre_rate.min(self.highest_rate));
        let penalty1 = usize::from(if self.rssi_sta_ra > RSSI_THRESHOLD[rate_id] {
            RETRY_PENALTY_IDX[0][rate_id]
        } else {
            RETRY_PENALTY_IDX[1][rate_id]
        });
        // u32 arithmetic matches `struct rtl8xxxu_ra_info` (u32 nsc_*/total).
        let penalty2 = usize::from(RETRY_PENALTY_UP_IDX[rate_id]);
        self.nsc_down = Self::score(self.nsc_down, &self.retry, self.total, penalty1);
        self.nsc_up = Self::score(self.nsc_up, &self.retry, self.total, penalty2);
        if self.nsc_down < u32::from(N_THRESHOLD_LOW[rate_id])
            || self.drop > u16::from(DROPPING_NECESSARY[rate_id])
        {
            self.rate_down();
        } else if self.nsc_up > u32::from(N_THRESHOLD_HIGH[rate_id]) {
            self.rate_up();
        }
        if self.decision_rate == self.pre_rate {
            self.dynamic_tx_rpt_timing_counter += 1;
        } else {
            self.dynamic_tx_rpt_timing_counter = 0;
        }
        if self.dynamic_tx_rpt_timing_counter >= 4 {
            self.set_tx_rpt_timing(Timing::Increase);
            self.dynamic_tx_rpt_timing_counter = 0;
        }
        self.pre_rate = self.decision_rate;
        self.reset_ra_counter();
    }
    fn score(mut nsc: u32, retry: &[u16; 5], total: u32, penalty: usize) -> u32 {
        for (r, p) in retry.iter().zip(RETRY_PENALTY[penalty]) {
            nsc = nsc.wrapping_add(u32::from(*r) * u32::from(p));
        }
        let floor = total.wrapping_mul(u32::from(RETRY_PENALTY[penalty][5]));
        nsc.saturating_sub(floor)
    }
    /// `rtl8188e_power_training_try_state`; upstream unconditionally
    /// disables power training afterwards (no false-alarm statistics).
    fn power_training_try_state(&mut self) {
        self.pt_try_state = match self.pt_mode_ss {
            3 => u8::from(self.decision_rate >= DESC_RATE_MCS13),
            2 => u8::from(self.decision_rate >= DESC_RATE_MCS5),
            1 => u8::from(self.decision_rate >= DESC_RATE_48M),
            0 => u8::from(self.decision_rate >= DESC_RATE_11M),
            _ => 0,
        };
        self.pt_pre_rate = self.decision_rate;
        self.pt_stage = 0;
        self.ra_stage = 0;
        self.pt_stop_count = 0;
    }
    /// `rtl8188e_power_training_decision`.
    fn power_training_decision(&mut self) {
        let mut numsc = 0u32;
        let num_total = self.total.wrapping_mul(u32::from(PT_PENALTY[5]));
        let mut j = 0u8;
        while j <= 4 {
            numsc += u32::from(self.retry[usize::from(j)]) * u32::from(PT_PENALTY[usize::from(j)]);
            if numsc > num_total {
                break;
            }
            j += 1;
        }
        j >>= 1;
        let temp = (self.pt_stage + 1) >> 1;
        let stage_id = temp.saturating_sub(j);
        let smooth = u16::from(self.pt_smooth_factor >> 1)
            + u16::from(self.pt_smooth_factor >> 2)
            + u16::from(stage_id) * 16
            + 2;
        self.pt_smooth_factor = smooth.min(192) as u8;
        let mut temp = ((self.pt_smooth_factor >> 6) * 2).saturating_sub(1);
        if self.drop > 3 {
            temp = 0;
        }
        self.pt_stage = temp;
    }
    /// `rtl8188e_handle_ra_tx_report2` for station mode (item 0 only).
    /// `length` is rxdesc16 `pktlen & 0x3ff`, `valid` the DW5:DW4
    /// `macid_valid` words. Returns the REG_TX_REPORT_TIME value to write
    /// when the minimum report time changed.
    pub fn report2(&mut self, length: usize, valid: u64, items: &[u8]) -> Option<u16> {
        let mut min_rpt_time = 0x927c;
        if length / TX_RPT2_ITEM_SIZE != 0 {
            if valid & 1 != 0 && items.len() >= TX_RPT2_ITEM_SIZE {
                self.retry[0] = u16::from_le_bytes([items[0], items[1]]);
                for i in 1..5 {
                    self.retry[i] = u16::from(items[i + 1]);
                }
                self.drop = u16::from(items[6]);
                self.total =
                    self.retry.iter().map(|r| u32::from(*r)).sum::<u32>() + u32::from(self.drop);
                if self.total > 0 {
                    match self.ra_stage {
                        0..=4 => self.rate_decision(),
                        5 => self.power_training_try_state(),
                        _ => self.power_training_decision(),
                    }
                    self.ra_stage = if self.ra_stage <= 5 {
                        self.ra_stage + 1
                    } else {
                        0
                    };
                }
            }
            min_rpt_time = min_rpt_time.min(self.rpt_time);
        }
        if min_rpt_time != self.pre_min_rpt_time {
            self.pre_min_rpt_time = min_rpt_time;
            Some(min_rpt_time)
        } else {
            None
        }
    }
}

/// `rtl8xxxu_refresh_rate_mask` RSSI levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Init,
    High,
    Mid,
    Low,
}
const NOISE_FLOOR_MIN: i32 = -100;
const SNR_THRESH_HIGH: u8 = 50;
const SNR_THRESH_LOW: u8 = 20;
/// `rtl8xxxu_signal_to_snr`.
pub fn signal_to_snr(signal: i32) -> u8 {
    (signal.clamp(NOISE_FLOOR_MIN, 0) - NOISE_FLOOR_MIN) as u8
}
/// `rtl8xxxu_refresh_rate_mask` level hysteresis.
pub fn level(previous: Level, signal: i32) -> Level {
    let snr = signal_to_snr(signal);
    let (mut high, mut low) = (SNR_THRESH_HIGH, SNR_THRESH_LOW);
    match previous {
        Level::Mid => high += 5,
        Level::Low => {
            high += 5;
            low += 5;
        }
        _ => {}
    }
    if snr > high {
        Level::High
    } else if snr > low {
        Level::Mid
    } else {
        Level::Low
    }
}
/// `rtl8xxxu_refresh_rate_mask` 2.4 GHz bitmap for a 1T1R RTL8188EU.
/// `legacy` is `supp_rates[0]` (DESC rate bits 0..11), `mcs` `rx_mask[0]`.
pub fn level_mask(level: Level, legacy: u16, mcs: u8, ht: bool) -> u32 {
    let mut bitmap = u32::from(legacy & 0xfff) | u32::from(mcs) << 12;
    let b = legacy <= 0xf;
    let bg = !b && legacy & 0xf != 0;
    if ht {
        if b || bg {
            // BGN 20MHz 1SS
            bitmap &= match level {
                Level::High => 0x000f0000,
                Level::Mid => 0x000ff000,
                _ => 0x000ff005,
            };
        } else {
            // GN 1SS: Linux applies no level mask.
        }
    } else if b {
        bitmap &= if bitmap & 0xc != 0 { 0xd } else { 0xf };
    } else if bg {
        bitmap &= match level {
            Level::High => 0x00000f00,
            Level::Mid => 0x00000ff0,
            _ => 0x00000ff5,
        };
    } else {
        bitmap &= if level == Level::High {
            0x00000f00
        } else {
            0x00000ff0
        };
    }
    bitmap
}
/// `DECLARE_EWMA(rssi, 10, 16)` over `-signal`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rssi(u32);
impl Rssi {
    pub fn add(&mut self, signal: i8) {
        let value = u32::from((-i32::from(signal)).clamp(0, 255) as u8);
        self.0 = if self.0 == 0 {
            value << 10
        } else {
            ((self.0 << 4) - self.0 + (value << 10)) >> 4
        };
    }
    /// `-ewma_rssi_read`.
    pub fn signal(&self) -> i32 {
        -((self.0 >> 10) as i32)
    }
}
/// `rtl8723au_rx_parse_phystats` signal for the RTL8188EU: CCK uses
/// `rtl8188e_cck_rssi` (LNA/VGA from `cck_agc_rpt_ofdm_cfosho_a`, TSMC
/// table below cut 8), OFDM `(cck_sig_qual_ofdm_pwdb_all >> 1) - 110`.
pub fn signal(phy: &[u8], rate: u8, cut: u8) -> Option<i8> {
    if rate < 4 {
        let agc = *phy.get(5)?;
        const SMIC: [i8; 8] = [17, -1, -13, -29, -32, -35, -38, -41];
        const TSMC: [i8; 8] = [29, 20, 12, 3, -6, -15, -24, -33];
        let lna = usize::from(agc >> 5);
        let vga = (agc & 31) as i8;
        let gain = if cut >= 8 { SMIC[lna] } else { TSMC[lna] };
        Some(gain.wrapping_sub(2 * vga))
    } else {
        Some(((*phy.get(4)? >> 1) as i8).wrapping_sub(110))
    }
}
