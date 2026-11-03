// SPDX-License-Identifier: GPL-2.0-or-later
//! Periodic dynamic-mechanism watchdog (`dm`, continuation tag `D`).
//!
//! Faithful port of Linux rtw88 `main.c::rtw_watch_dog_work` (2s period) and
//! `phy.c::rtw_phy_dynamic_mechanism`: statistics (RSSI EWMA, false alarms),
//! DIG, CCK packet-detection, RA/RRSR tracking, TX path diversity, CFO,
//! thermal RF power tracking (with LCK) and EDCCA adaptivity, using the
//! per-chip ops from `rtw8822c.c` (`false_alarm_statistics`, `cck_pd_set`,
//! `cfo_track`, `pwr_track`, `adaptivity`, `config_tx_path`) and
//! `rtw8821c.c` (`false_alarm_statistics`, `cck_pd_set`). RTL8822C DPK
//! calibration and `rtw8822c_dpk_track` live in [`super::dpk`] (bit 7).
//!
//! Nothing here runs without a separately signed `N2xD` continuation
//! ([`KIND`]); its payload selects the mechanisms and their measured bounds.
//! Every register group runs under [`Authority::run`]; H2C commands are
//! returned to the caller, which sends them through the retained mailbox.
use super::firmware_transport::{Error, Io};
use super::packet_format::DataProfile;
use super::qualification::{Kind, PAYLOAD};
use alloc::vec::Vec;

pub(super) const DIG: u16 = 1 << 0;
pub(super) const CCK_PD: u16 = 1 << 1;
pub(super) const RA: u16 = 1 << 2;
pub(super) const PATH_DIV: u16 = 1 << 3;
pub(super) const CFO: u16 = 1 << 4;
pub(super) const PWR_TRACK: u16 = 1 << 5;
pub(super) const EDCCA: u16 = 1 << 6;
pub(super) const DPK: u16 = 1 << 7;
const C21_MECHANISMS: u16 = DIG | CCK_PD | RA;
const C22_MECHANISMS: u16 = DIG | CCK_PD | RA | PATH_DIV | CFO | PWR_TRACK | EDCCA | DPK;
/// RTL8822BE: `rtw8822b_dig` (0xc50/0xe50), the 8821C-identical
/// `rtw8822b_false_alarm_statistics`, RA and `rtw8822b_pwr_track`
/// ([`super::tracking8822b`]; its re-IQK needs the separate `N2BW`). 8822B
/// has no `cck_pd_set`, no `config_tx_path`/CFO/DPK hooks. `rtw8822b_adaptivity`
/// EDCCA writes 0x8a4 byte0/byte1 (`rtw8822b_edcca_th`, offset 0).
const B22_MECHANISMS: u16 = DIG | RA | PWR_TRACK | EDCCA;
/// Linux `RTW_WATCH_DOG_DELAY_TIME`.
pub(super) const PERIOD_MS: u64 = 2000;

pub(super) static KIND: Kind = Kind {
    tag: b'D',
    stem: "dm",
    source: SOURCE,
    admit,
};
const SOURCE: &[u8] = b"Linux rtw88 v6.12 main.c rtw_watch_dog_work 2s; phy.c rtw_phy_dynamic_mechanism: \
rtw_phy_statistics EWMA rssi(10,16) rssi_level{20,34,38,42,46,50,100}+3 H2C42; false alarm 8822c 1c3c/1a5c/2d04..2d20 reset 1a2c/1d2c/1eb4, 8821c 808/a5c/f48 reset 9a4/a2c/b58; \
rtw_phy_dig perf250/500/750 0x5a/0x40 cvrg2000/4000/5000 0x2a/0x26/0x1c offset15 damping 5/9 steps4/3/2(6/4/2) -2; dig 8822c 1d70 7f/7f00 min0x20, 8821c c50 7f min0x1c; \
rtw_phy_cck_pd fa_avg (3a+b)/4 lv1>1000 lv0<500 igi38/2a/24 rssi32/32/24, 8822c pd{0,2,4,6,8} cs{0,2,2,2,4} 1ac8/1acc/1ad0 max255/31 err27/29, 8821c a08 3f0000 {3,7,13,13,13} aa8 1f0000 aaa+2lv; \
rtw_phy_ra_track H2C58 wl_phy_info, every4th RA_INFO40 no_update rssi masks fff0/efe0/cfc0/8f80/0f00 recover, C2H0c ra report, rrsr 440=init&genmask(order+3); \
8822c tx path diversity path_a/b rssi avg 1a04 f0000000 8/4, 820 ff 31/32, 1e2c ffff 0400, bb reset 2 bit0; \
8822c cfo tail*2.5 avg enable20 stop10 adj10 xcap 1040 23:10 x|x<<7, only BT disabled scoreboard aa bit1, single station else step to efuse; \
8822c pwr_track type0 RF42 bit19 trigger then 7e EWMA thermal(10,4) delta<=29 type0 2g/cck swing tables 18a0/41a0 7f, lck>=8 bb/b0/ca/c9/cc; \
8822c adaptivity normal l2h=max(igi+8,48) h2l-8, ETSI 45/JP60 l2h=igi+12 or ini h2l-7 84c byte2/3 +0x80; \
8822c phy_calibration rfk_power_save + do_dpk on rf18 channel change (reload same ch): bb backup 520..41a4 rf 0/1a/55/63/87/8f/de, \
tx_pause 522=ff 1e70=2, dpk_mac_bb/afe_is_dpk/afe_no_dpk tables, pre_setting 1b08 1f100000|1f0d0000 1be4 3b23170b 1be8 775f5347, \
gnt_wl 70 bit26 + ltecoex 38 byte1 77, one-shot 1b00 cmd 0x14/16/1a/1c +path (+2 bw80) <<8|48 then 2d9c==55, cal_pwr 1bb4 bit12 1bfc bit31, \
gainloss rxbb dc 92 84800/1, dc corr 200/40..65, pas_agc dgain 1535/768 loss 0x4000000 log2 db 250/1000 txbb -2/+3 cnt6, \
coef 20x 1bd4 tbl, saturate 1000/0fff fallback 1fff/04001fff, txagc-6 1b67, gs dgain*910>>10 /10 rounded, coef1 0x16c00/gs 1b18, \
enable 1b08/1b60 bit31 gs; dpk_track ewma thermal(10,4) delta-k_delta 1b58[6:0] bounded by payload window; restore dpd off";

/// RTL8822BE dm contract (`N2BD`), hashed with [`SOURCE`] for B22 requests.
pub(super) const SOURCE8822B: &[u8] = b"RTL8822BE N2BD: rtw8822b.c rtw8822b_false_alarm_statistics 808 bit28 a5c/f48/f04/f14/f10/f0c/f08/fcc, reset 9a4 bit17 set-clr, a2c bit15 clr-set, b58 bit0 set-clr; rtw8822b_dig c50/e50 7f both paths, dig_min 0x1c; query_phy_status_page0 PWDB w0[15:8]-110 path A, page1 PWDB A w0[15:8] B w0[23:16] -110 rssi over 2 paths; RA H2C42/58/40 + rrsr; no cck_pd_set, no tx path diversity, no cfo, no dpk; rtw8822b_pwr_track type0 bit5: RF42[17:16]=3 trigger, next pass RF-A 42[15:10] inside N2BD and N2BP windows, EWMA thermal(10,4), init_trigger or avg!=sample, delta=min(|avg-efuse A|,29) one meter both paths, rtw8822b_pwrtrk_2g{a,b}_{p,n}/2g_cck tables bounded by N2BD power_up/down, rtw8822b_pwrtrack_set with the committed channel TXAGC index offset 3f-index, txagc_swing_offset max 0xf upper default+10, c94/e94[29:25] c1c/e1c[31:21] rtw8822b_txscale_tbl, default_ofdm_index from c1c (rtw8822b_get_swing_index else 24), base fields restored; need_iqk threshold 8 only through N2BW; rtw8822b_adaptivity bit6: rtw_phy_adaptivity_set_mode ETSI l2h_th_ini_ad -14+50=36, JP l2h_th_ini_cs 10+50=60, else normal; normal l2h=max(igi+8,48) h2l=l2h-8, adaptivity l2h=min(igi,ini) h2l=l2h-7; rtw8822b_edcca_th 8a4 byte0 l2h byte1 h2l offset0; base 8a4[15:0] (rtw8822b_adaptivity_init 7f/7f) restored";

fn admit(did: u16, p: &[u8; PAYLOAD]) -> bool {
    bounds(did, p).is_some()
}

/// Measured envelope carried by the signed payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Bounds {
    pub(super) enabled: u16,
    /// Highest IGI the DIG program may select.
    pub(super) dig_max: u8,
    /// Highest CCK packet-detection level (0..=4).
    pub(super) cck_pd_max: u8,
    /// Largest |crystal - factory crystal| CFO tracking may apply.
    pub(super) xtal_window: u8,
    /// Largest positive/negative power-tracking index delta.
    pub(super) power_up: u8,
    pub(super) power_down: u8,
    /// Thermal-meter envelope [lo, hi] the program was measured over.
    pub(super) thermal: [u8; 2],
    /// Largest |DPK PWSF offset| `rtw8822c_dpk_track` may apply (DPK only).
    pub(super) dpk_window: u8,
}

pub(super) fn bounds(did: u16, p: &[u8; PAYLOAD]) -> Option<Bounds> {
    let (allowed, dig_min) = match did {
        0xc821 => (C21_MECHANISMS, 0x1c),
        0xc822 => (C22_MECHANISMS, 0x20),
        0xb822 => (B22_MECHANISMS, 0x1c),
        _ => return None,
    };
    let b = Bounds {
        enabled: u16::from_le_bytes([p[0], p[1]]),
        dig_max: p[2],
        cck_pd_max: p[3],
        xtal_window: p[4],
        power_up: p[5],
        power_down: p[6],
        thermal: [p[7], p[8]],
        dpk_window: p[9],
    };
    if b.enabled == 0
        || b.enabled & !allowed != 0
        || !(dig_min..=DIG_PERF_MAX).contains(&b.dig_max)
        || b.cck_pd_max > 4
        || b.xtal_window > 0x3f
        || b.power_up > 0x3f
        || b.power_down > 0x3f
        || b.thermal[0] > b.thermal[1]
        || b.thermal[1] > 63
        || b.dpk_window > 0x3f
        || (b.enabled & DPK == 0 && b.dpk_window != 0)
        || p[10..].iter().any(|&v| v != 0)
    {
        return None;
    }
    Some(b)
}

/// Factory/radio facts of the exact retained base the tracker runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Facts {
    pub(super) did: u16,
    pub(super) rfe: u8,
    /// Factory crystal (`efuse.crystal_cap`), 7 bits.
    pub(super) crystal: u8,
    /// Factory thermal meters (`efuse.thermal_meter[]`), 0xff when erased.
    pub(super) thermal: [u8; 2],
    /// `efuse.power_track_type`; tracking runs only for type 0.
    pub(super) power_track_type: u8,
    /// Calibrated CCK gain-index bounds (`dm_info.cck_gi_{l,u}_bnd`).
    pub(super) cck_gi: [u8; 2],
}
impl Facts {
    fn c22(&self) -> bool {
        self.did == 0xc822
    }
    fn b22(&self) -> bool {
        self.did == 0xb822
    }
    fn paths(&self) -> usize {
        if self.c22() {
            2
        } else {
            1
        }
    }
    fn thermal_k(&self) -> u8 {
        if self.c22() {
            ((u16::from(self.thermal[0]) + u16::from(self.thermal[1])) >> 1) as u8
        } else {
            self.thermal[0]
        }
    }
}

/// Runs one register group under the current continuation/base authority.
pub(super) trait Authority {
    fn run<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error>;
    /// RTL8822BE committed-channel per-path coded TXAGC indices (DESC_RATE
    /// 0..11) `rtw8822b_pwrtrack_set` offsets against.
    fn b22_indices(&self) -> Option<[[u8; 12]; 2]> {
        None
    }
    /// RTL8822BE `N2BP` measured thermal windows.
    fn b22_temperature(&self, _: u8) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}

const DIG_PERF_FA_TH_LOW: u16 = 250;
const DIG_PERF_FA_TH_HIGH: u16 = 500;
const DIG_PERF_FA_TH_EXTRA_HIGH: u16 = 750;
const DIG_PERF_MAX: u8 = 0x5a;
const DIG_PERF_MID: u8 = 0x40;
const DIG_CVRG_FA_TH_LOW: u16 = 2000;
const DIG_CVRG_FA_TH_HIGH: u16 = 4000;
const DIG_CVRG_FA_TH_EXTRA_HIGH: u16 = 5000;
const DIG_CVRG_MAX: u8 = 0x2a;
const DIG_CVRG_MID: u8 = 0x26;
const DIG_CVRG_MIN: u8 = 0x1c;
const DIG_RSSI_GAIN_OFFSET: u8 = 15;
const CCK_FA_AVG_RESET: u32 = u32::MAX;
const CCK_PD_LV_MAX: u8 = 5;
const RTW_PWR_TRK_TBL_SZ: u8 = 30;
const RRSR_RATE_ORDER_MAX: u32 = 0xfffff;
const EDCCA_TH_L2H_LB: i16 = 48;
const EDCCA_ADC_BACKOFF: i16 = 12;
const EDCCA_IGI_L2H_DIFF: i16 = 8;
const EDCCA_L2H_H2L_DIFF: i16 = 7;
const EDCCA_L2H_H2L_DIFF_NORMAL: i16 = 8;
const CFO_TRK_ENABLE_TH: i32 = 20;
const CFO_TRK_STOP_TH: i32 = 10;
const CFO_TRK_ADJ_TH: i32 = 10;
const LCK_THRESHOLD: u8 = 8;

// rtw8822c_table.c rtw8822c_pwrtrk_2g{a,b}_{p,n} and _2g_cck_{a,b}_{p,n}.
const PWRTRK_2GA_P: [u8; 30] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 25, 26, 27,
];
const PWRTRK_2GA_N: [u8; 30] = [
    0, 1, 2, 2, 3, 4, 4, 5, 6, 6, 7, 8, 8, 9, 9, 10, 11, 11, 12, 13, 13, 14, 15, 15, 16, 17, 17,
    18, 19, 19,
];
const PWRTRK_2GB_P: [u8; 30] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28,
];
const PWRTRK_2GB_N: [u8; 30] = [
    0, 1, 2, 3, 4, 4, 5, 6, 7, 8, 9, 9, 10, 11, 12, 13, 14, 15, 15, 16, 17, 18, 19, 20, 20, 21, 22,
    23, 24, 25,
];
const PWRTRK_2G_CCK_A_P: [u8; 30] = [
    0, 1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 11, 12, 13, 14, 15, 16, 17, 18, 18, 19, 20, 21, 22,
    23, 24, 24, 25,
];
const PWRTRK_2G_CCK_A_N: [u8; 30] = [
    0, 1, 2, 3, 3, 4, 5, 6, 6, 7, 8, 9, 9, 10, 11, 12, 12, 13, 14, 15, 15, 16, 17, 18, 18, 19, 20,
    21, 21, 22,
];
const PWRTRK_2G_CCK_B_P: [u8; 30] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29,
];
const PWRTRK_2G_CCK_B_N: [u8; 30] = [
    0, 1, 2, 3, 4, 5, 5, 6, 7, 8, 9, 10, 11, 11, 12, 13, 14, 15, 16, 17, 17, 18, 19, 20, 21, 22,
    23, 23, 24, 25,
];
// rtw8822c_cck_pd_reg[bw][nrx] = (reg_pd, mask_pd, reg_cs, mask_cs).
const CCK_PD_REG: [[(u16, u32, u16, u32); 2]; 2] = [
    [
        (0x1ac8, 0x00ff, 0x1ad0, 0x01f),
        (0x1ac8, 0xff00, 0x1ad0, 0x3e0),
    ],
    [
        (0x1acc, 0x00ff, 0x1ad0, 0x01F0_0000),
        (0x1acc, 0xff00, 0x1ad0, 0x3E00_0000),
    ],
];
// phy.c db_invert_table.
const DB_INVERT: [[u32; 8]; 12] = [
    [10, 13, 16, 20, 25, 32, 40, 50],
    [64, 80, 101, 128, 160, 201, 256, 318],
    [401, 505, 635, 800, 1007, 1268, 1596, 2010],
    [316, 398, 501, 631, 794, 1000, 1259, 1585],
    [1995, 2512, 3162, 3981, 5012, 6310, 7943, 10000],
    [12589, 15849, 19953, 25119, 31623, 39811, 50119, 63098],
    [
        79433, 100000, 125893, 158489, 199526, 251189, 316228, 398107,
    ],
    [
        501187, 630957, 794328, 1000000, 1258925, 1584893, 1995262, 2511886,
    ],
    [
        3162278, 3981072, 5011872, 6309573, 7943282, 1000000, 12589254, 15848932,
    ],
    [
        19952623, 25118864, 31622777, 39810717, 50118723, 63095734, 79432823, 100000000,
    ],
    [
        125892541, 158489319, 199526232, 251188643, 316227766, 398107171, 501187234, 630957345,
    ],
    [
        794328235, 1000000000, 1258925412, 1584893192, 1995262315, 2511886432, 3162277660,
        3981071706,
    ],
];
// rtw8821c.c lna_gain_table_{0,1}.
const LNA_GAIN_0: [i8; 8] = [22, 8, -6, -22, -31, -40, -46, -52];
const LNA_GAIN_1: [i8; 16] = [
    10, 6, 2, -2, -6, -10, -14, -17, -20, -24, -28, -31, -34, -37, -40, -44,
];

fn power_2_db(power: i8) -> u8 {
    if power <= -100 || power >= 20 {
        0
    } else if power >= 0 {
        100
    } else {
        (100 + i16::from(power)) as u8
    }
}
fn db_2_linear(db: u8) -> u64 {
    let db = db.min(96);
    if db < 1 {
        return 1;
    }
    let i = usize::from((db - 1) >> 3);
    let j = usize::from((db - 1) - ((i as u8) << 3));
    let linear = u64::from(DB_INVERT[i][j]);
    if i > 2 {
        linear << 3
    } else {
        linear
    }
}
fn linear_2_db(linear: u64) -> u8 {
    let mut found = None;
    'outer: for (i, row) in DB_INVERT.iter().enumerate() {
        for (j, &t) in row.iter().enumerate() {
            let t = u64::from(t);
            if (i <= 2 && (linear << 3) <= t) || (i > 2 && linear <= t) {
                found = Some((i, j));
                break 'outer;
            }
        }
    }
    let Some((mut i, mut j)) = found else {
        return 96;
    };
    if !(i == 0 && j == 0) {
        let t = |a: usize, b: usize| u64::from(DB_INVERT[a][b]);
        if j == 0 {
            if t(i, 0).wrapping_sub(linear) > linear.wrapping_sub(t(i - 1, 7)) {
                i -= 1;
                j = 7;
            }
        } else if t(i, j).wrapping_sub(linear) > linear.wrapping_sub(t(i, j - 1)) {
            j -= 1;
        }
    }
    ((i << 3) + j + 1) as u8
}
/// `phy.c::rtw_phy_rf_power_2_rssi`.
pub(super) fn rf_power_2_rssi(power: &[i8]) -> u8 {
    let mut sum: u64 = power.iter().map(|&p| db_2_linear(power_2_db(p))).sum();
    sum = (sum + (1 << 2)) >> 3;
    if power.len() == 2 {
        sum >>= 1;
    }
    linear_2_db(sum)
}

/// Linux `DECLARE_EWMA(name, 10, weight)` with `weight` a power of two.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Ewma {
    internal: u64,
}
impl Ewma {
    pub(super) fn add(&mut self, value: u8, shift: u32) {
        let v = u64::from(value) << 10;
        self.internal = if self.internal == 0 {
            v
        } else {
            ((self.internal << shift) - self.internal + v) >> shift
        };
    }
    pub(super) fn read(&self) -> u8 {
        (self.internal >> 10).min(255) as u8
    }
}

/// One received PHY-status sample from the current peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Sample {
    pub(super) rssi: u8,
    pub(super) path_rssi: [Option<u8>; 2],
    pub(super) cfo_tail: Option<[i8; 2]>,
    pub(super) rate: u8,
}

/// Decode an original 32-byte PHY-status record (Linux
/// `query_phy_status_page{0,1}` for rtw8822c / rtw8821c).
pub(super) fn sample(facts: &Facts, rate: u8, status: &[u8; 32]) -> Option<Sample> {
    let page = status[0] & 15;
    let word = |w: usize| u32::from_le_bytes(status[w * 4..w * 4 + 4].try_into().unwrap());
    if facts.b22() {
        // `rtw8822b.c::query_phy_status_page0/1`: PWDB word0[15:8] (page 1
        // path B word0[23:16]) - 110; CCK uses path A only.
        let pwdb = |shift: u32| ((((word(0) >> shift) & 0xff) as i16) - 110) as i8;
        return match page {
            0 => Some(Sample {
                rssi: rf_power_2_rssi(&[pwdb(8)]),
                path_rssi: [None, None],
                cfo_tail: None,
                rate,
            }),
            1 => {
                let power = [pwdb(8), pwdb(16)];
                Some(Sample {
                    rssi: rf_power_2_rssi(&power),
                    path_rssi: [None, None],
                    cfo_tail: None,
                    rate,
                })
            }
            _ => None,
        };
    }
    if facts.c22() {
        match page {
            0 => {
                let mut power = [
                    ((word(0) >> 8) & 0xff) as u8 as i8 as i16,
                    (word(4) & 0xff) as u8 as i8 as i16,
                ];
                let gains = [
                    ((word(0) >> 16) & 0x3f) as u8,
                    ((word(4) >> 24) & 0x3f) as u8,
                ];
                let [l, u] = facts.cck_gi;
                for (p, g) in power.iter_mut().zip(gains) {
                    if g < l {
                        *p += i16::from(l - g) << 1;
                    } else if g > u {
                        *p -= i16::from(g - u) << 1;
                    }
                    *p -= 110;
                }
                let power = power.map(|p| p as i8);
                Some(Sample {
                    rssi: rf_power_2_rssi(&power[..1]),
                    path_rssi: [None, None],
                    cfo_tail: None,
                    rate,
                })
            }
            1 => {
                let power = [
                    ((((word(0) >> 8) & 0xff) as i16) - 110) as i8,
                    ((((word(0) >> 16) & 0xff) as i16) - 110) as i8,
                ];
                Some(Sample {
                    rssi: rf_power_2_rssi(&power),
                    path_rssi: [
                        Some(rf_power_2_rssi(&power[..1])),
                        Some(rf_power_2_rssi(&power[1..])),
                    ],
                    cfo_tail: Some([status[20] as i8, status[21] as i8]),
                    rate,
                })
            }
            _ => None,
        }
    } else {
        match page {
            0 => {
                let vga = ((word(3) >> 8) & 0x1f) as i16;
                let lna = ((((word(3) >> 23) & 1) << 3) | ((word(3) >> 13) & 7)) as usize;
                let gain = if facts.rfe == 0 {
                    LNA_GAIN_0.get(lna).copied()
                } else {
                    LNA_GAIN_1.get(lna).copied()
                };
                let power = gain.map_or(-120, |g| (i16::from(g) - 2 * vga) as i8);
                Some(Sample {
                    rssi: rf_power_2_rssi(&[power]),
                    path_rssi: [None, None],
                    cfo_tail: None,
                    rate,
                })
            }
            1 => {
                let power = ((((word(0) >> 8) & 0xff) as i16) - 110) as i8;
                Some(Sample {
                    rssi: rf_power_2_rssi(&[power]),
                    path_rssi: [None, None],
                    cfo_tail: None,
                    rate,
                })
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EdccaMode {
    Normal,
    /// ETSI/JP adaptivity with the chip `l2h_th_ini_{ad,cs}`.
    Adaptivity(i16),
}
/// `phy.c::rtw_phy_adaptivity_set_mode` from the regulatory DFS region with
/// the RTL8822C `l2h_th_ini_{cs,ad}` (60/45).
pub(super) fn edcca_mode(country: [u8; 2]) -> EdccaMode {
    edcca_mode_with(country, 60, 45)
}
/// RTL8822B `rtw8822b_hw_spec` `l2h_th_ini_cs` = 10 + `EDCCA_IGI_BASE` and
/// `l2h_th_ini_ad` = -14 + `EDCCA_IGI_BASE` (50).
pub(super) fn edcca_mode8822b(country: [u8; 2]) -> EdccaMode {
    edcca_mode_with(country, 10 + 50, -14 + 50)
}
/// The country→DFS region mapping follows wireless-regdb `DFS-ETSI`/`DFS-JP`:
/// ETSI takes `l2h_th_ini_ad`, JP `l2h_th_ini_cs`, others normal EDCCA.
fn edcca_mode_with(country: [u8; 2], cs: i16, ad: i16) -> EdccaMode {
    const ETSI: &[[u8; 2]] = &[
        *b"AT", *b"BE", *b"BG", *b"CH", *b"CY", *b"CZ", *b"DE", *b"DK", *b"EE", *b"ES", *b"FI",
        *b"FR", *b"GB", *b"GR", *b"HR", *b"HU", *b"IE", *b"IS", *b"IT", *b"LI", *b"LT", *b"LU",
        *b"LV", *b"MT", *b"NL", *b"NO", *b"PL", *b"PT", *b"RO", *b"SE", *b"SI", *b"SK",
    ];
    if country == *b"JP" {
        EdccaMode::Adaptivity(cs)
    } else if ETSI.contains(&country) {
        EdccaMode::Adaptivity(ad)
    } else {
        EdccaMode::Normal
    }
}

/// Watchdog inputs supplied by the station for one period.
#[derive(Clone, Copy, Debug)]
pub(super) struct Period {
    pub(super) linked: bool,
    pub(super) profile: DataProfile,
    pub(super) tx_bytes: u64,
    pub(super) rx_bytes: u64,
    pub(super) country: [u8; 2],
    /// `hal.txrx_1ss` (coexistence `config_trx_mode(A, A)`) is in effect:
    /// 1SS TX path diversity is held on path A.
    pub(super) txrx_1ss: bool,
}

/// Linux `rtw_dm_info`/`rtw_cfo_track`/`rtw_path_div` subset.
pub(super) struct Tracker {
    bounds: Bounds,
    facts: Facts,
    initialized: bool,
    count: u32,
    rssi: Ewma,
    rssi_level: u8,
    min_rssi: u8,
    pre_min_rssi: u8,
    igi_history: [u8; 4],
    fa_history: [u16; 4],
    igi_bitmap: u8,
    damping: bool,
    damping_cnt: u8,
    damping_rssi: u8,
    total_fa: u16,
    cck_fa: u32,
    cck_fa_avg: u32,
    cck_pd_lv: [[u8; 2]; 2],
    cck_pd_default: u8,
    rrsr_init: u32,
    tx_rate: u8,
    rx_rate: u8,
    tx_tp: Ewma,
    rx_tp: Ewma,
    path_sum: [u32; 2],
    path_cnt: [u32; 2],
    tx_path: u8,
    crystal: u8,
    cfo_adjust: bool,
    cfo_tail: [i32; 2],
    cfo_cnt: [u32; 2],
    packet_count: u32,
    packet_count_pre: u32,
    thermal: [Ewma; 2],
    pwr_triggered: bool,
    thermal_lck: u8,
    delta_power: [i8; 2],
    base_igi: u8,
    base_edcca: u32,
    dpk: Option<super::dpk::Dpk>,
    /// RTL8822BE `rtw8822b_pwr_track` state and the base TXAGC/scale fields.
    b22_power: Option<(super::tracking8822b::Tracker, super::tracking8822b::Base)>,
    /// `rtw_phy_pwrtrack_need_iqk` fired: the caller runs the `N2BW` IQK.
    iqk_due: bool,
}

impl Tracker {
    pub(super) fn new(bounds: Bounds, facts: Facts) -> Self {
        Self {
            bounds,
            facts,
            initialized: false,
            count: 0,
            rssi: Ewma::default(),
            rssi_level: 0,
            min_rssi: u8::MAX,
            pre_min_rssi: u8::MAX,
            igi_history: [0; 4],
            fa_history: [0; 4],
            igi_bitmap: 0,
            damping: false,
            damping_cnt: 0,
            damping_rssi: 0,
            total_fa: 0,
            cck_fa: 0,
            cck_fa_avg: CCK_FA_AVG_RESET,
            cck_pd_lv: [[0; 2]; 2],
            cck_pd_default: 0,
            rrsr_init: 0,
            tx_rate: 0,
            rx_rate: 0,
            tx_tp: Ewma::default(),
            rx_tp: Ewma::default(),
            path_sum: [0; 2],
            path_cnt: [0; 2],
            tx_path: 1,
            crystal: facts.crystal,
            cfo_adjust: true,
            cfo_tail: [0; 2],
            cfo_cnt: [0; 2],
            packet_count: 0,
            packet_count_pre: 0,
            thermal: [Ewma::default(); 2],
            pwr_triggered: false,
            thermal_lck: facts.thermal_k(),
            delta_power: [0; 2],
            base_igi: 0,
            base_edcca: 0,
            dpk: (facts.c22() && bounds.enabled & DPK != 0)
                .then(|| super::dpk::Dpk::new(bounds.dpk_window, bounds.thermal)),
            b22_power: None,
            iqk_due: false,
        }
    }
    /// Whether `rtw_phy_pwrtrack_need_iqk` fired in the last period; the
    /// flag is consumed.
    pub(super) fn take_iqk(&mut self) -> bool {
        core::mem::take(&mut self.iqk_due)
    }
    pub(super) fn bounds(&self) -> Bounds {
        self.bounds
    }
    fn on(&self, bit: u16) -> bool {
        self.bounds.enabled & bit != 0
    }
    pub(super) fn igi(&self) -> u8 {
        self.igi_history[0]
    }
    pub(super) fn min_rssi(&self) -> u8 {
        self.min_rssi
    }
    pub(super) fn crystal(&self) -> u8 {
        self.crystal
    }
    pub(super) fn tx_path(&self) -> u8 {
        self.tx_path
    }
    pub(super) fn delta_power(&self) -> [i8; 2] {
        self.delta_power
    }
    #[cfg(feature = "kernel-test")]
    pub(super) fn dpk(&self) -> Option<&super::dpk::Dpk> {
        self.dpk.as_ref()
    }
    pub(super) fn pd_level(&self) -> u8 {
        self.cck_pd_lv[0][0]
    }
    /// `rx.c::rtw_rx_addr_match_iter` + `rtw_phy_parsing_cfo` + the
    /// page-1 path-diversity accumulation for one frame from the peer.
    pub(super) fn observe(&mut self, s: Sample) {
        self.rssi.add(s.rssi, 4);
        self.rx_rate = s.rate;
        for (path, r) in s.path_rssi.iter().enumerate() {
            if let Some(r) = r {
                self.path_sum[path] += u32::from(*r);
                self.path_cnt[path] += 1;
            }
        }
        if let Some(tail) = s.cfo_tail {
            for (path, t) in tail.iter().enumerate().take(self.facts.paths()) {
                self.cfo_tail[path] += i32::from(*t);
                self.cfo_cnt[path] += 1;
            }
            self.packet_count = self.packet_count.wrapping_add(1);
        }
    }
    /// `fw.c::rtw_fw_ra_report_handle` (C2H 0x0c, report size 7).
    pub(super) fn c2h(&mut self, body: &[u8]) -> bool {
        if body.len() < 2 + 7 || body[0] != 0x0c || body[3] != 0 {
            return false;
        }
        self.tx_rate = body[2] & 0x7f;
        true
    }

    async fn read(io: &mut impl Io, reg: u16) -> Result<u32, Error> {
        super::radio::read(io, reg).await
    }
    async fn mask(io: &mut impl Io, reg: u16, bits: u32, value: u32) -> Result<(), Error> {
        super::radio::mask(io, reg, bits, value).await
    }
    async fn get(io: &mut impl Io, reg: u16, bits: u32) -> Result<u32, Error> {
        Ok((Self::read(io, reg).await? & bits) >> bits.trailing_zeros())
    }
    async fn dig_write(&self, io: &mut impl Io, igi: u8) -> Result<(), Error> {
        if self.facts.c22() {
            Self::mask(io, 0x1d70, 0x7f, u32::from(igi)).await?;
            Self::mask(io, 0x1d70, 0x7f00, u32::from(igi)).await
        } else if self.facts.b22() {
            // `rtw_phy_dig_write` over `rtw8822b_dig[]`, both paths.
            Self::mask(io, 0xc50, 0x7f, u32::from(igi)).await?;
            Self::mask(io, 0xe50, 0x7f, u32::from(igi)).await
        } else {
            Self::mask(io, 0xc50, 0x7f, u32::from(igi)).await
        }
    }
    async fn rf_write(
        io: &mut impl Io,
        auth: &impl Authority,
        path: u8,
        address: u8,
        bits: u32,
        value: u32,
    ) -> Result<(), Error> {
        let reg = (if path == 0 { 0x3c00 } else { 0x4c00 }) + u16::from(address) * 4;
        crate::rtw88::firmware_transport::enclosed(
            |op| auth.run(op),
            Self::mask(io, reg, bits, value),
        )
        .await?;
        io.delay_us(1).await;
        Ok(())
    }
    async fn rf_read(io: &mut impl Io, path: u8, address: u8) -> Result<u32, Error> {
        super::radio::rf_read(io, path, address).await
    }

    /// `phy.c::rtw_phy_init` subset plus `rtw8822c_cfo_init` and
    /// `rtw8821c` `cck_pd_default`, against the current retained registers.
    async fn init(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        let c22 = self.facts.c22();
        crate::rtw88::firmware_transport::enclosed(|op| auth.run(op), async {
            self.igi_history = [0; 4];
            self.fa_history = [0; 4];
            self.igi_bitmap = 0;
            self.igi_history[0] = if c22 {
                Self::get(io, 0x1d70, 0x7f).await? as u8
            } else {
                Self::get(io, 0xc50, 0x7f).await? as u8
            };
            if self.facts.did == 0xc821 {
                let v = io.read8(0xaaa).await?;
                if v == 255 {
                    return Err(Error::Gone);
                }
                self.cck_pd_default = v & 0x1f;
            }
            self.base_igi = self.igi_history[0];
            if c22 {
                self.base_edcca = Self::read(io, 0x84c).await? & 0xffff_0000;
            } else if self.facts.b22() {
                self.base_edcca = Self::read(io, 0x8a4).await? & 0xffff;
            }
            if self.facts.b22() && self.bounds.enabled & PWR_TRACK != 0 {
                // rtw8822b_pwrtrack_init over the retained base program.
                let default = super::radio8822b::pwrtrack_init(io).await?;
                let base = super::tracking8822b::Base::capture(io).await?;
                self.b22_power = Some((
                    super::tracking8822b::Tracker::new(self.facts.thermal[0], default),
                    base,
                ));
            }
            self.rrsr_init = Self::read(io, 0x440).await?;
            Ok(())
        })
        .await?;
        self.iqk_due = false;
        self.cck_pd_lv = [[0; 2]; 2];
        self.cck_fa_avg = CCK_FA_AVG_RESET;
        self.crystal = self.facts.crystal;
        self.cfo_adjust = true;
        self.tx_path = 1;
        self.initialized = true;
        Ok(())
    }

    async fn false_alarm(&mut self, io: &mut impl Io) -> Result<(), Error> {
        if self.facts.c22() {
            let cck_enable = Self::read(io, 0x1c3c).await? & 2 != 0;
            let cck = io.read16(0x1a5c).await?;
            if cck == u16::MAX {
                return Err(Error::Gone);
            }
            let mut w = [0; 5];
            for (v, r) in w.iter_mut().zip([0x2d04, 0x2d08, 0x2d0c, 0x2d10, 0x2d20]) {
                *v = Self::read(io, r).await?;
            }
            let lo = |v: u32| v & 0xffff;
            let hi = |v: u32| v >> 16;
            let ofdm = hi(w[0])
                + lo(w[1])
                + hi(w[1])
                + lo(w[2])
                + lo(w[3])
                + hi(w[3])
                + lo(w[4])
                + hi(w[4]);
            self.cck_fa = u32::from(cck);
            let total = ofdm + if cck_enable { u32::from(cck) } else { 0 };
            self.total_fa = total.min(u32::from(u16::MAX)) as u16;
            Self::mask(io, 0x1a2c, 0xc000, 0).await?;
            Self::mask(io, 0x1a2c, 0xc000, 2).await?;
            Self::mask(io, 0x1a2c, 0x3000, 0).await?;
            Self::mask(io, 0x1a2c, 0x3000, 2).await?;
            Self::mask(io, 0x1d2c, 1 << 31, 0).await?;
            Self::mask(io, 0x1eb4, 1 << 25, 1).await?;
            Self::mask(io, 0x1eb4, 1 << 25, 0).await?;
            Self::mask(io, 0x1d2c, 1 << 31, 1).await?;
        } else {
            let cck_enable = Self::read(io, 0x808).await? & (1 << 28) != 0;
            let cck = io.read16(0xa5c).await?;
            let ofdm = io.read16(0xf48).await?;
            if cck == u16::MAX || ofdm == u16::MAX {
                return Err(Error::Gone);
            }
            self.cck_fa = u32::from(cck);
            let total = u32::from(ofdm) + if cck_enable { u32::from(cck) } else { 0 };
            self.total_fa = total.min(u32::from(u16::MAX)) as u16;
            Self::mask(io, 0x9a4, 1 << 17, 1).await?;
            Self::mask(io, 0x9a4, 1 << 17, 0).await?;
            Self::mask(io, 0xa2c, 1 << 15, 0).await?;
            Self::mask(io, 0xa2c, 1 << 15, 1).await?;
            Self::mask(io, 0xb58, 1, 1).await?;
            Self::mask(io, 0xb58, 1, 0).await?;
        }
        Ok(())
    }

    /// `phy.c::rtw_phy_get_rssi_level`.
    fn rssi_level(old: u8, rssi: u8) -> u8 {
        let mut table = [20u8, 34, 38, 42, 46, 50, 100];
        for (i, t) in table.iter_mut().enumerate() {
            if i >= usize::from(old) {
                *t += 3;
            }
        }
        table.iter().position(|&t| rssi < t).unwrap_or(0) as u8
    }

    fn check_damping(&mut self) -> bool {
        let min_rssi = self.min_rssi;
        if self.damping {
            let diff = min_rssi.abs_diff(self.damping_rssi);
            let count = self.damping_cnt;
            self.damping_cnt = self.damping_cnt.saturating_add(1);
            if diff > 3 || count > 20 {
                self.damping = false;
                return false;
            }
            return true;
        }
        let i = self.igi_history;
        let f = self.fa_history;
        let (lo, hi) = (DIG_PERF_FA_TH_LOW, DIG_PERF_FA_TH_HIGH);
        let damping = match self.igi_bitmap & 0xf {
            5 => {
                i[0] > i[1]
                    && i[2] > i[3]
                    && i[0] - i[1] >= 2
                    && i[2] - i[3] >= 2
                    && f[0] > hi
                    && f[1] < lo
                    && f[2] > hi
                    && f[3] < lo
            }
            9 => {
                i[0] > i[1]
                    && i[3] > i[2]
                    && i[0] - i[1] >= 4
                    && i[3] - i[2] >= 2
                    && f[0] > hi
                    && f[1] < lo
                    && f[2] < lo
                    && f[3] > hi
            }
            _ => return false,
        };
        if damping {
            self.damping = true;
            self.damping_cnt = 0;
            self.damping_rssi = min_rssi;
        }
        damping
    }

    /// `phy.c::rtw_phy_dig` with the signed upper bound applied to `DIG_PERF_MAX`.
    async fn dig(&mut self, io: &mut impl Io, linked: bool) -> Result<(), Error> {
        if self.check_damping() {
            return Ok(());
        }
        let fa = self.total_fa;
        let pre = self.igi_history[0];
        let (th, step) = if linked {
            (
                [
                    DIG_PERF_FA_TH_EXTRA_HIGH,
                    DIG_PERF_FA_TH_HIGH,
                    DIG_PERF_FA_TH_LOW,
                ],
                if self.pre_min_rssi > self.min_rssi {
                    [6u8, 4, 2]
                } else {
                    [4, 3, 2]
                },
            )
        } else {
            (
                [
                    DIG_CVRG_FA_TH_EXTRA_HIGH,
                    DIG_CVRG_FA_TH_HIGH,
                    DIG_CVRG_FA_TH_LOW,
                ],
                [4, 3, 2],
            )
        };
        let mut igi = pre;
        for level in 0..3 {
            if fa > th[level] {
                igi = igi.wrapping_add(step[level]);
                break;
            }
        }
        igi = igi.wrapping_sub(2);
        let chip_min = if self.facts.c22() { 0x20 } else { 0x1c };
        let (max, mid, min, rssi) = if linked {
            (
                DIG_PERF_MAX.min(self.bounds.dig_max),
                DIG_PERF_MID,
                chip_min,
                self.min_rssi.max(chip_min),
            )
        } else {
            (DIG_CVRG_MAX, DIG_CVRG_MID, DIG_CVRG_MIN, DIG_CVRG_MIN)
        };
        let max = max.min(rssi.saturating_add(DIG_RSSI_GAIN_OFFSET));
        let lower = rssi.clamp(min, mid.max(min));
        let upper = lower
            .saturating_add(DIG_RSSI_GAIN_OFFSET)
            .clamp(min, max.max(min));
        // Linux clamp_t(lower, upper) = min(max(v, lower), upper).
        let igi = igi.max(lower).min(upper);
        // rtw_phy_dig_recorder
        let up = u8::from(igi > self.igi_history[0]);
        self.igi_bitmap = ((self.igi_bitmap << 1) & 0xfe) | up;
        self.igi_history = [
            igi,
            self.igi_history[0],
            self.igi_history[1],
            self.igi_history[2],
        ];
        self.fa_history = [
            fa,
            self.fa_history[0],
            self.fa_history[1],
            self.fa_history[2],
        ];
        if igi != pre {
            self.dig_write(io, igi).await?;
        }
        Ok(())
    }

    fn pd_target(&self, linked: bool) -> u8 {
        let avg = self.cck_fa_avg;
        if linked {
            let igi = self.igi_history[0];
            let rssi = self.min_rssi;
            if igi > 0x38 && rssi > 32 {
                return 4;
            }
            if igi > 0x2a && rssi > 32 {
                return 3;
            }
            if igi > 0x24 || rssi > 24 {
                return 2;
            }
        }
        if avg > 1000 {
            1
        } else if avg < 500 {
            0
        } else {
            CCK_PD_LV_MAX
        }
    }

    /// `phy.c::rtw_phy_cck_pd` (2.4GHz retained channel) + chip `cck_pd_set`.
    async fn cck_pd(&mut self, io: &mut impl Io, linked: bool) -> Result<(), Error> {
        let fa = self.cck_fa;
        self.cck_fa_avg = if self.cck_fa_avg == CCK_FA_AVG_RESET {
            fa
        } else {
            ((u64::from(self.cck_fa_avg) * 3 + u64::from(fa)) >> 2) as u32
        };
        let mut level = self.pd_target(linked);
        if level >= CCK_PD_LV_MAX {
            return Ok(());
        }
        level = level.min(self.bounds.cck_pd_max);
        if self.facts.c22() {
            const PD: [i32; 5] = [0, 2, 4, 6, 8];
            const CS: [i32; 5] = [0, 2, 2, 2, 4];
            let nrx = Self::get(io, 0x1a2c, 0x60000).await? as usize;
            let bw = Self::get(io, 0x9b0, 0xc).await? as usize;
            if bw > 1 || nrx > 1 {
                return Err(Error::Unsupported);
            }
            let cur = self.cck_pd_lv[bw][nrx];
            if cur == level {
                return Ok(());
            }
            self.cck_fa_avg = CCK_FA_AVG_RESET;
            let (rpd, mpd, rcs, mcs) = CCK_PD_REG[bw][nrx];
            let mut pd = Self::get(io, rpd, mpd).await? as i32;
            let mut cs = Self::get(io, rcs, mcs).await? as i32;
            pd += PD[usize::from(level)] - PD[usize::from(cur)];
            cs += CS[usize::from(level)] - CS[usize::from(cur)];
            pd = pd.clamp(0, 255);
            if cs == 27 || cs == 29 {
                cs += 1;
            } else {
                cs = cs.clamp(0, 31);
            }
            Self::mask(io, rpd, mpd, pd as u32).await?;
            Self::mask(io, rcs, mcs, cs as u32).await?;
            self.cck_pd_lv[bw][nrx] = level;
        } else {
            const PD: [u32; 5] = [3, 7, 13, 13, 13];
            if self.cck_pd_lv[0][0] == level {
                return Ok(());
            }
            self.cck_fa_avg = CCK_FA_AVG_RESET;
            self.cck_pd_lv[0][0] = level;
            Self::mask(io, 0xa08, 0x3f0000, PD[usize::from(level)]).await?;
            Self::mask(
                io,
                0xaa8,
                0x1f0000,
                (u32::from(self.cck_pd_default) + u32::from(level) * 2).min(0x1f),
            )
            .await?;
        }
        Ok(())
    }

    /// `phy.c::rtw_phy_get_rrsr_mask`.
    fn rrsr_mask(rate: u8) -> u32 {
        let mut order = if rate >= 44 {
            (rate - 44) % 10
        } else if rate >= 12 {
            (rate - 12) % 8
        } else if rate >= 4 {
            rate - 4
        } else {
            rate
        };
        if rate >= 12 || order == 0 {
            order += 1;
        }
        (1u32 << (u32::from(order) + 4)) - 1
    }

    /// `rtw8822c_config_cck_tx_path`/`config_ofdm_tx_path` for 1SS
    /// diversity over the two-path TX configuration, then `bb_reset`.
    async fn set_tx_path(io: &mut impl Io, path: u8) -> Result<(), Error> {
        async fn bb_reset(io: &mut impl Io) -> Result<(), Error> {
            let old = io_read16(io, 2).await?;
            for v in [old | 1, old & !1, old | 1] {
                Io::write16(io, 2, v).await?;
            }
            Ok(())
        }
        Self::mask(io, 0x1a04, 0xf000_0000, if path == 1 { 8 } else { 4 }).await?;
        bb_reset(io).await?;
        Self::mask(io, 0x820, 0xff, if path == 1 { 0x31 } else { 0x32 }).await?;
        Self::mask(io, 0x1e2c, 0xffff, 0x0400).await?;
        bb_reset(io).await
    }

    /// Return 1SS TX path diversity to path A before coexistence programs
    /// `config_trx_mode(A, A)`; [`Period::txrx_1ss`] then holds it there
    /// until the 1SS fields are restored. Linux keeps running
    /// `rtw_phy_tx_path_diversity` (it checks only `hal.antenna_rx`), which
    /// could select path B while ORITXCODE2/RX run path A only; here the
    /// two owners never write the same fields at once. Runs under the base
    /// gate like [`Self::restore`].
    pub(super) async fn hold_tx_path(
        &mut self,
        io: &mut impl Io,
        base: &impl Authority,
    ) -> Result<(), Error> {
        self.path_sum = [0; 2];
        self.path_cnt = [0; 2];
        if !self.initialized || !self.facts.c22() || !self.on(PATH_DIV) || self.tx_path == 1 {
            return Ok(());
        }
        crate::rtw88::firmware_transport::enclosed(|op| base.run(op), Self::set_tx_path(io, 1))
            .await?;
        self.tx_path = 1;
        Ok(())
    }

    /// `rtw8822c_set_crystal_cap` bounded by the measured window.
    async fn set_crystal(&mut self, io: &mut impl Io, cap: u8) -> Result<(), Error> {
        let f = self.facts.crystal;
        let w = self.bounds.xtal_window;
        let cap = cap.clamp(f.saturating_sub(w), f.saturating_add(w).min(0x7f));
        if cap == self.crystal {
            return Ok(());
        }
        let v = u32::from(cap) | (u32::from(cap) << 7);
        Self::mask(io, 0x1040, 0x00ff_fc00, v).await?;
        self.crystal = cap;
        Ok(())
    }

    async fn cfo(&mut self, io: &mut impl Io, linked: bool) -> Result<(), Error> {
        if !linked {
            // rtw8822c_cfo_tracking_reset
            self.cfo_adjust = true;
            let f = self.facts.crystal;
            if self.crystal > f {
                self.set_crystal(io, self.crystal - 1).await?;
            } else if self.crystal < f {
                self.set_crystal(io, self.crystal + 1).await?;
            }
            return Ok(());
        }
        if self.packet_count == self.packet_count_pre {
            return Ok(());
        }
        self.packet_count_pre = self.packet_count;
        let paths = self.facts.paths();
        let mut sum = 0i32;
        for p in 0..paths {
            let khz = (self.cfo_tail[p] << 1) + (self.cfo_tail[p] >> 1);
            sum += if self.cfo_cnt[p] != 0 {
                khz / self.cfo_cnt[p] as i32
            } else {
                0
            };
            self.cfo_tail[p] = 0;
            self.cfo_cnt[p] = 0;
        }
        let avg = sum / paths as i32;
        if !self.cfo_adjust {
            if avg.abs() > CFO_TRK_ENABLE_TH {
                self.cfo_adjust = true;
            }
        } else if avg.abs() <= CFO_TRK_STOP_TH {
            self.cfo_adjust = false;
        }
        // rtw_coex_disabled: scoreboard REG_WIFI_BT_INFO & ~BT_INT_EN, ONOFF bit1.
        let score = io_read16(io, 0xaa).await? & !(1 << 15);
        if score & 2 != 0 {
            self.cfo_adjust = false;
            return self.set_crystal(io, self.facts.crystal).await;
        }
        if self.cfo_adjust {
            let mut cap = i16::from(self.crystal);
            if avg > CFO_TRK_ADJ_TH {
                cap += 1;
            } else if avg < -CFO_TRK_ADJ_TH {
                cap -= 1;
            }
            self.set_crystal(io, cap.clamp(0, 0x7f) as u8).await?;
        }
        Ok(())
    }

    async fn adaptivity(&self, io: &mut impl Io, mode: EdccaMode) -> Result<(), Error> {
        let igi = i16::from(self.igi_history[0]);
        let (l2h, h2l) = match mode {
            EdccaMode::Normal => {
                let l2h = (igi + EDCCA_IGI_L2H_DIFF).max(EDCCA_TH_L2H_LB);
                (l2h, l2h - EDCCA_L2H_H2L_DIFF_NORMAL)
            }
            EdccaMode::Adaptivity(ini) => {
                let l2h = if igi < ini - EDCCA_ADC_BACKOFF {
                    igi + EDCCA_ADC_BACKOFF
                } else {
                    ini
                };
                (l2h, l2h - EDCCA_L2H_H2L_DIFF)
            }
        };
        let byte = |v: i16| ((v as i8 as i32 + 0x80) & 0xff) as u32;
        Self::mask(io, 0x84c, 0x00ff_0000, byte(l2h)).await?;
        Self::mask(io, 0x84c, 0xff00_0000, byte(h2l)).await
    }

    /// `rtw8822b_adaptivity`: normal `max(igi + 8, 48)`/`- 8`, adaptivity
    /// `min(igi, l2h_th_ini)`/`- 7`, through `rtw_phy_set_edcca_th` over
    /// `rtw8822b_edcca_th` (0x8a4 byte0 L2H, byte1 H2L, offset 0).
    pub(super) fn edcca8822b(igi: u8, mode: EdccaMode) -> (u8, u8) {
        let igi = i16::from(igi);
        let (l2h, h2l) = match mode {
            EdccaMode::Normal => {
                let l2h = (igi + EDCCA_IGI_L2H_DIFF).max(EDCCA_TH_L2H_LB);
                (l2h, l2h - EDCCA_L2H_H2L_DIFF_NORMAL)
            }
            EdccaMode::Adaptivity(ini) => {
                let l2h = igi.min(ini);
                (l2h, l2h - EDCCA_L2H_H2L_DIFF)
            }
        };
        // `s8` arguments to `u8 l2h, u8 h2l`.
        (l2h as i8 as u8, h2l as i8 as u8)
    }
    async fn adaptivity8822b(&self, io: &mut impl Io, mode: EdccaMode) -> Result<(), Error> {
        let (l2h, h2l) = Self::edcca8822b(self.igi_history[0], mode);
        Self::mask(io, 0x8a4, 0xff, u32::from(l2h)).await?;
        Self::mask(io, 0x8a4, 0xff00, u32::from(h2l)).await
    }

    fn swing(&self, path: usize) -> (&'static [u8; 30], &'static [u8; 30]) {
        if self.tx_rate <= 3 {
            if path == 0 {
                (&PWRTRK_2G_CCK_A_P, &PWRTRK_2G_CCK_A_N)
            } else {
                (&PWRTRK_2G_CCK_B_P, &PWRTRK_2G_CCK_B_N)
            }
        } else if path == 0 {
            (&PWRTRK_2GA_P, &PWRTRK_2GA_N)
        } else {
            (&PWRTRK_2GB_P, &PWRTRK_2GB_N)
        }
    }

    /// `rtw8822c_do_lck`.
    async fn lck(io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        let full = 0xfffff;
        Self::rf_write(io, auth, 0, 0xbb, full, 0x80010).await?;
        Self::rf_write(io, auth, 0, 0xb0, full, 0x1f0fa).await?;
        io.delay_us(1).await;
        Self::rf_write(io, auth, 0, 0xca, full, 0x80000).await?;
        Self::rf_write(io, auth, 0, 0xc9, full, 0x80001).await?;
        for _ in 0..100 {
            io.delay_us(1000).await;
            if crate::rtw88::firmware_transport::enclosed(
                |op| auth.run(op),
                Self::rf_read(io, 0, 0xca),
            )
            .await?
                & 0x1000
                == 0
            {
                break;
            }
        }
        Self::rf_write(io, auth, 0, 0xb0, full, 0x1f0f8).await?;
        Self::rf_write(io, auth, 1, 0xbb, full, 0x80010).await?;
        Self::rf_write(io, auth, 0, 0xcc, full, 0x0f000).await?;
        Self::rf_write(io, auth, 0, 0xcc, full, 0x4f000).await?;
        io.delay_us(1).await;
        Self::rf_write(io, auth, 0, 0xcc, full, 0x0f000).await
    }

    /// `rtw8822c_pwr_track`. Returns Prerequisite outside the measured
    /// thermal envelope; the caller then restores the base program.
    async fn pwr_track(&mut self, io: &mut impl Io, auth: &impl Authority) -> Result<(), Error> {
        if self.facts.power_track_type != 0 {
            return Ok(());
        }
        if !self.pwr_triggered {
            for path in 0..2 {
                for v in [1, 0, 1] {
                    Self::rf_write(io, auth, path, 0x42, 1 << 19, v).await?;
                }
            }
            self.pwr_triggered = true;
            return Ok(());
        }
        self.pwr_triggered = false;
        for path in 0..2 {
            if self.facts.thermal[path] == 0xff {
                continue;
            }
            let t = ((crate::rtw88::firmware_transport::enclosed(
                |op| auth.run(op),
                Self::rf_read(io, path as u8, 0x42),
            )
            .await?
                & 0x7e)
                >> 1) as u8;
            if !(self.bounds.thermal[0]..=self.bounds.thermal[1]).contains(&t) {
                return Err(Error::Prerequisite);
            }
            self.thermal[path].add(t, 2);
        }
        let avg0 = self.thermal[0].read();
        if avg0.abs_diff(self.thermal_lck) >= LCK_THRESHOLD {
            self.thermal_lck = avg0;
            Self::lck(io, auth).await?;
        }
        for path in 0..2 {
            let efuse = self.facts.thermal[path];
            if efuse == 0xff {
                continue;
            }
            let avg = self.thermal[path].read();
            let delta = avg.abs_diff(efuse).min(RTW_PWR_TRK_TBL_SZ - 1);
            let (p, n) = self.swing(path);
            let index = if avg > efuse {
                p[usize::from(delta)] as i8
            } else {
                -(n[usize::from(delta)] as i8)
            };
            let index = index.clamp(-(self.bounds.power_down as i8), self.bounds.power_up as i8);
            self.delta_power[path] = index;
            let reg = if path == 0 { 0x18a0 } else { 0x41a0 };
            crate::rtw88::firmware_transport::enclosed(
                |op| auth.run(op),
                Self::mask(io, reg, 0x7f, (index as u8 & 0x7f).into()),
            )
            .await?;
        }
        Ok(())
    }

    /// `rtw8822b_pwr_track` over the retained [`super::tracking8822b`]
    /// state, for the RA-reported `dm_info->tx_rate`.
    async fn pwr_track8822b(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
    ) -> Result<(), Error> {
        let indices = auth.b22_indices().ok_or(Error::State)?;
        let limits = super::tracking8822b::Limits {
            thermal: self.bounds.thermal,
            up: self.bounds.power_up,
            down: self.bounds.power_down,
        };
        let tx_rate = self.tx_rate;
        let (tracker, _) = self.b22_power.as_mut().ok_or(Error::State)?;
        let pass = tracker
            .pass(
                io,
                auth,
                indices,
                |t| auth.b22_temperature(t),
                limits,
                tx_rate,
            )
            .await?;
        self.delta_power = tracker.delta_power();
        if let super::tracking8822b::Pass::Tracked { iqk: true, .. } = pass {
            self.iqk_due = true;
        }
        Ok(())
    }

    /// `rtw_update_sta_info(.., false)` RA_INFO refresh from the current
    /// qualified data profile with the RSSI-level mask (`main.c`).
    fn ra_info(&self, profile: DataProfile) -> [u8; 8] {
        let bak = profile.ra_mask();
        let cck_only = profile.mcs == 0 && profile.rates & !0xf == 0;
        let level_mask: u32 = if cck_only {
            u32::MAX
        } else {
            match self.rssi_level {
                0 => u32::MAX,
                1 => 0xffff_fff0,
                2 => 0xffff_efe0,
                3 => 0xffff_cfc0,
                4 => 0xffff_8f80,
                _ => 0xffff_0f00,
            }
        };
        let mut mask = bak & level_mask;
        if mask & !0xfff == 0 {
            mask |= bak & !0xfff;
        }
        if mask == 0 {
            mask |= bak & 0xfff;
        }
        let m = mask.to_le_bytes();
        [
            0x40,
            0,
            profile.rate_id() | (u8::from(profile.sgi) << 7),
            // DIS_PT | NO_UPDATE | BW_MODE (`si->bw_mode`, N2xB 40MHz).
            0x48 | (u8::from(profile.vht.is_some()) << 4) | profile.bw_mode(),
            m[0],
            m[1],
            m[2],
            m[3],
        ]
    }

    /// Restore the base receive/transmit program after authority loss or an
    /// out-of-envelope sample. Runs under the base gate only.
    pub(super) async fn restore(
        &mut self,
        io: &mut impl Io,
        base: &impl Authority,
    ) -> Result<(), Error> {
        if !self.initialized {
            return Ok(());
        }
        let c22 = self.facts.c22();
        crate::rtw88::firmware_transport::enclosed(|op| base.run(op), async {
            if self.on(DIG) {
                self.dig_write(io, self.base_igi).await?;
                self.igi_history[0] = self.base_igi;
            }
            if c22 && self.on(EDCCA) {
                Self::mask(io, 0x84c, 0xffff_0000, self.base_edcca >> 16).await?;
            }
            if self.facts.b22() && self.on(EDCCA) {
                Self::mask(io, 0x8a4, 0xffff, self.base_edcca).await?;
            }
            if c22 && self.on(CFO) {
                self.set_crystal(io, self.facts.crystal).await?;
            }
            if c22 && self.on(PATH_DIV) && self.tx_path != 1 {
                Self::mask(io, 0x1a04, 0xf000_0000, 8).await?;
                Self::mask(io, 0x820, 0xff, 0x11).await?;
                Self::mask(io, 0x1e2c, 0xff, 0).await?;
                self.tx_path = 1;
            }
            if c22 && self.on(PWR_TRACK) {
                Self::mask(io, 0x18a0, 0x7f, 0).await?;
                Self::mask(io, 0x41a0, 0x7f, 0).await?;
                self.delta_power = [0; 2];
            }
            if let Some((_, base)) = self.b22_power.take() {
                base.restore(io).await?;
                self.delta_power = [0; 2];
            }
            if self.on(RA) && self.rrsr_init != 0 {
                io.write32(0x440, self.rrsr_init).await?;
            }
            Ok(())
        })
        .await?;
        if self.on(CCK_PD) {
            self.cck_pd_restore(io, base).await?;
        }
        if let Some(dpk) = self.dpk.as_mut() {
            dpk.restore(io, base).await?;
        }
        self.initialized = false;
        Ok(())
    }
    async fn cck_pd_restore(
        &mut self,
        io: &mut impl Io,
        base: &impl Authority,
    ) -> Result<(), Error> {
        let saved = self.bounds.cck_pd_max;
        let avg = self.cck_fa_avg;
        // Return every tracked bw/nrx slot to level0 through the source delta path.
        crate::rtw88::firmware_transport::enclosed(|op| base.run(op), async {
            if self.facts.c22() {
                const PD: [i32; 5] = [0, 2, 4, 6, 8];
                const CS: [i32; 5] = [0, 2, 2, 2, 4];
                for (bw, regs) in CCK_PD_REG.iter().enumerate() {
                    for (nrx, &(rpd, mpd, rcs, mcs)) in regs.iter().enumerate() {
                        let cur = self.cck_pd_lv[bw][nrx];
                        if cur == 0 {
                            continue;
                        }
                        let pd = (Self::get(io, rpd, mpd).await? as i32 - PD[usize::from(cur)])
                            .clamp(0, 255);
                        let cs = (Self::get(io, rcs, mcs).await? as i32 - CS[usize::from(cur)])
                            .clamp(0, 31);
                        Self::mask(io, rpd, mpd, pd as u32).await?;
                        Self::mask(io, rcs, mcs, cs as u32).await?;
                        self.cck_pd_lv[bw][nrx] = 0;
                    }
                }
            } else if self.cck_pd_lv[0][0] != 0 {
                Self::mask(io, 0xa08, 0x3f0000, 3).await?;
                Self::mask(io, 0xaa8, 0x1f0000, u32::from(self.cck_pd_default)).await?;
                self.cck_pd_lv[0][0] = 0;
            }
            Ok(())
        })
        .await?;
        self.bounds.cck_pd_max = saved;
        self.cck_fa_avg = avg;
        Ok(())
    }

    /// One `rtw_watch_dog_work` period. Returns the H2C commands
    /// (RSSI monitor, WL PHY info, periodic RA info) for the caller to send.
    pub(super) async fn tick(
        &mut self,
        io: &mut impl Io,
        auth: &impl Authority,
        period: Period,
    ) -> Result<Vec<[u8; 8]>, Error> {
        if !self.initialized {
            self.init(io, auth).await?;
        }
        let c22 = self.facts.c22();
        let mut h2c = Vec::new();
        // Traffic statistics (rtw_watch_dog_work).
        self.tx_tp.add((period.tx_bytes >> 18).min(255) as u8, 1);
        self.rx_tp.add((period.rx_bytes >> 18).min(255) as u8, 1);
        // rtw_phy_statistics
        if period.linked {
            let rssi = self.rssi.read();
            self.rssi_level = Self::rssi_level(self.rssi_level, rssi);
            if self.on(RA) {
                h2c.push([0x42, 0, 0, rssi, 0, 0, 0, 0]);
            }
            self.pre_min_rssi = self.min_rssi;
            self.min_rssi = rssi;
        } else {
            self.pre_min_rssi = self.min_rssi;
            self.min_rssi = u8::MAX;
        }
        crate::rtw88::firmware_transport::enclosed(|op| auth.run(op), self.false_alarm(io)).await?;
        if self.on(DIG) {
            crate::rtw88::firmware_transport::enclosed(
                |op| auth.run(op),
                self.dig(io, period.linked),
            )
            .await?;
        }
        if self.on(CCK_PD) {
            crate::rtw88::firmware_transport::enclosed(
                |op| auth.run(op),
                self.cck_pd(io, period.linked),
            )
            .await?;
        }
        if self.on(RA) {
            // rtw_fw_update_wl_phy_info
            let tx = u32::from(self.tx_tp.read()) & 0x3ff;
            let rx = u32::from(self.rx_tp.read()) & 0x3ff;
            let w0 = (tx << 8 | rx << 18).to_le_bytes();
            h2c.push([0x58, w0[1], w0[2], w0[3], self.tx_rate, self.rx_rate, 0, 0]);
            if period.linked && self.count & 3 == 0 {
                h2c.push(self.ra_info(period.profile));
            }
            if period.linked {
                let mask = Self::rrsr_mask(self.tx_rate).min(RRSR_RATE_ORDER_MAX);
                let value = self.rrsr_init & mask;
                if value != 0 {
                    crate::rtw88::firmware_transport::enclosed(
                        |op| auth.run(op),
                        io.write32(0x440, value),
                    )
                    .await?;
                }
            }
        }
        if period.txrx_1ss {
            // The coexistence 1SS owner holds the TX path (`hold_tx_path`).
            self.path_sum = [0; 2];
            self.path_cnt = [0; 2];
        } else if c22 && self.on(PATH_DIV) && period.linked {
            // rtw_phy_tx_path_div_select
            let avg = |s: u32, c: u32| if c != 0 { s / c } else { 0 };
            let a = avg(self.path_sum[0], self.path_cnt[0]);
            let b = avg(self.path_sum[1], self.path_cnt[1]);
            let mut path = self.tx_path;
            if a != b {
                path = if a > b { 1 } else { 2 };
            }
            self.path_sum = [0; 2];
            self.path_cnt = [0; 2];
            if path != self.tx_path {
                crate::rtw88::firmware_transport::enclosed(
                    |op| auth.run(op),
                    Self::set_tx_path(io, path),
                )
                .await?;
                self.tx_path = path;
            }
        }
        if c22 && self.on(CFO) {
            crate::rtw88::firmware_transport::enclosed(
                |op| auth.run(op),
                self.cfo(io, period.linked),
            )
            .await?;
        }
        // rtw_phy_dpk_track sits between CFO and power tracking.
        if let Some(dpk) = self.dpk.as_mut() {
            dpk.period(io, auth).await?;
        }
        if c22 && self.on(PWR_TRACK) {
            self.pwr_track(io, auth).await?;
        }
        if self.facts.b22() && self.on(PWR_TRACK) && self.facts.power_track_type == 0 {
            self.pwr_track8822b(io, auth).await?;
        }
        if c22 && self.on(EDCCA) {
            let mode = edcca_mode(period.country);
            crate::rtw88::firmware_transport::enclosed(
                |op| auth.run(op),
                self.adaptivity(io, mode),
            )
            .await?;
        }
        if self.facts.b22() && self.on(EDCCA) {
            let mode = edcca_mode8822b(period.country);
            crate::rtw88::firmware_transport::enclosed(
                |op| auth.run(op),
                self.adaptivity8822b(io, mode),
            )
            .await?;
        }
        self.count = self.count.wrapping_add(1);
        Ok(h2c)
    }
}

async fn io_read16(io: &mut impl Io, reg: u16) -> Result<u16, Error> {
    let v = io.read16(reg).await?;
    if v == u16::MAX {
        Err(Error::Gone)
    } else {
        Ok(v)
    }
}
