// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2012 Realtek Corporation.
//! RTL8821A two-antenna coexistence: halbtc8821a2ant.{c,h}.
//! Local source C SHA256 ffbdd27e82137e67073afbdd2218d2f89de0c3628d24ec5701b94d0920611390.
//! Header SHA256 1fb4358c5c31931dcd7ce52473ae54e8c85477a043afd77329b196dd7b1433c7.
//! Version20130618/0x5050. Native registration and qualification are separate.
//! File statics and adaptive histories are instance owned. Debugfs rendering
//! is omitted; non-debug hardware reads and source ordering remain.

use super::btc::{
    Algorithm, Associate, BtReg, ChipInterface, Ctx, Hal, Ips, Lps, Media, Packet, Pnp, PowerSave,
    RssiState, Scan, WifiBw, BTC_ANTENNA_AT_MAIN_PORT, BTC_ANT_WIFI_AT_AUX, BTC_ANT_WIFI_AT_MAIN,
    BTC_RF_A, FORCE_EXEC, NORMAL_EXEC, WIFI_P2P_GO_CONNECTED,
};
use crate::rtlwifi::prepare::Error;

pub const BT_INFO_B_FTP: u8 = 1 << 7;
pub const BT_INFO_B_A2DP: u8 = 1 << 6;
pub const BT_INFO_B_HID: u8 = 1 << 5;
pub const BT_INFO_B_SCO_BUSY: u8 = 1 << 4;
pub const BT_INFO_B_ACL_BUSY: u8 = 1 << 3;
pub const BT_INFO_B_INQ_PAGE: u8 = 1 << 2;
pub const BT_INFO_B_SCO_ESCO: u8 = 1 << 1;
pub const BT_INFO_B_CONNECTION: u8 = 1 << 0;

/// `BTC_RSSI_COEX_THRESH_TOL_8821A_2ANT`.
pub const RSSI_COEX_THRESH_TOL: i32 = 2;
/// `BT_8821A_2ANT_WIFI_RSSI_COEXSWITCH_THRES`.
pub const WIFI_RSSI_COEXSWITCH_THRES: u8 = 42;
/// `BT_8821A_2ANT_BT_RSSI_COEXSWITCH_THRES`.
pub const BT_RSSI_COEXSWITCH_THRES: u8 = 46;

/// `enum BT_INFO_SRC_8821A_2ANT`.
pub const BT_INFO_SRC_WIFI_FW: usize = 0;
pub const BT_INFO_SRC_BT_RSP: usize = 1;
pub const BT_INFO_SRC_BT_ACTIVE_SEND: usize = 2;
pub const BT_INFO_SRC_MAX: usize = 3;

/// H2C element ids this algorithm sends.
pub const H2C_TDMA: u8 = 0x60;
pub const H2C_BT_INFO: u8 = 0x61;
pub const H2C_DEC_BT_PWR: u8 = 0x62;
pub const H2C_IGNORE_WLAN_ACT: u8 = 0x63;
pub const H2C_DAC_SWING: u8 = 0x64;
pub const H2C_ANT_SEL: u8 = 0x65;
pub const H2C_WIFI_CHNL: u8 = 0x66;
pub const H2C_BT_AUTO_REPORT: u8 = 0x68;
pub const H2C_LOW_PENALTY_RA: u8 = 0x69;
pub const H2C_BT_CALIBRATION: u8 = 0x6e;

/// `enum BT_8821A_2ANT_BT_STATUS`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BtStatus {
    #[default]
    Idle = 0,
    ConIdle = 1,
    NonIdle = 2,
    AclBusy = 3,
    ScoBusy = 4,
    AclScoBusy = 5,
    Max = 6,
}

/// `enum BT_8821A_2ANT_COEX_ALGO`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CoexAlgo {
    #[default]
    Undefined = 0,
    Sco = 1,
    Hid = 2,
    A2dp = 3,
    A2dpPanHs = 4,
    PanEdr = 5,
    PanHs = 6,
    PanEdrA2dp = 7,
    PanEdrHid = 8,
    HidA2dpPanEdr = 9,
    HidA2dp = 10,
    Max = 11,
}

/// `struct coex_dm_8821a_2ant`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoexDm {
    pub pre_dec_bt_pwr_lvl: bool,
    pub cur_dec_bt_pwr_lvl: bool,
    pub pre_fw_dac_swing_lvl: u8,
    pub cur_fw_dac_swing_lvl: u8,
    pub cur_ignore_wlan_act: bool,
    pub pre_ignore_wlan_act: bool,
    pub pre_ps_tdma: u8,
    pub cur_ps_tdma: u8,
    pub ps_tdma_para: [u8; 5],
    pub ps_tdma_du_adj_type: u8,
    pub reset_tdma_adjust: bool,
    pub auto_tdma_adjust: bool,
    pub pre_ps_tdma_on: bool,
    pub cur_ps_tdma_on: bool,
    pub pre_bt_auto_report: bool,
    pub cur_bt_auto_report: bool,
    pub pre_rf_rx_lpf_shrink: bool,
    pub cur_rf_rx_lpf_shrink: bool,
    pub bt_rf0x1e_backup: u32,
    pub pre_low_penalty_ra: bool,
    pub cur_low_penalty_ra: bool,
    pub pre_dac_swing_on: bool,
    pub pre_dac_swing_lvl: u32,
    pub cur_dac_swing_on: bool,
    pub cur_dac_swing_lvl: u32,
    pub pre_adc_back_off: bool,
    pub cur_adc_back_off: bool,
    pub pre_agc_table_en: bool,
    pub cur_agc_table_en: bool,
    pub pre_val0x6c0: u32,
    pub cur_val0x6c0: u32,
    pub pre_val0x6c4: u32,
    pub cur_val0x6c4: u32,
    pub pre_val0x6c8: u32,
    pub cur_val0x6c8: u32,
    pub pre_val0x6cc: u8,
    pub cur_val0x6cc: u8,
    pub limited_dig: bool,
    pub pre_algorithm: CoexAlgo,
    pub cur_algorithm: CoexAlgo,
    pub bt_status: BtStatus,
    pub wifi_chnl_info: [u8; 3],
    pub pre_lps: u8,
    pub cur_lps: u8,
    pub pre_rpwm: u8,
    pub cur_rpwm: u8,
}

/// `struct coex_sta_8821a_2ant`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoexSta {
    pub bt_link_exist: bool,
    pub sco_exist: bool,
    pub a2dp_exist: bool,
    pub hid_exist: bool,
    pub pan_exist: bool,
    pub under_lps: bool,
    pub under_ips: bool,
    pub high_priority_tx: u32,
    pub high_priority_rx: u32,
    pub low_priority_tx: u32,
    pub low_priority_rx: u32,
    pub bt_rssi: u8,
    pub bt_tx_rx_mask: bool,
    /// Zero-initialised in Linux: `BTC_RSSI_STATE_HIGH`.
    pub pre_bt_rssi_state: RssiState,
    pub pre_wifi_rssi_state: [RssiState; 4],
    pub c2h_bt_info_req_sent: bool,
    pub bt_info_c2h: [[u8; 10]; BT_INFO_SRC_MAX],
    pub bt_info_c2h_cnt: [u32; BT_INFO_SRC_MAX],
    pub c2h_bt_inquiry_page: bool,
    pub bt_retry_cnt: u8,
    pub bt_info_ext: u8,
    pub crc_ok_cck: u32,
    pub crc_ok_11g: u32,
    pub crc_ok_11n: u32,
    pub crc_ok_11n_agg: u32,
    pub crc_err_cck: u32,
    pub crc_err_11g: u32,
    pub crc_err_11n: u32,
    pub crc_err_11n_agg: u32,
    pub coex_table_type: u8,
    pub force_lps_on: bool,
    pub dis_ver_info_cnt: u8,
}

/// The Linux function-local statics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Statics {
    /// `btc8821a2ant_is_wifi_status_changed`.
    pub pre_wifi_busy: bool,
    pub pre_under_4way: bool,
    pub pre_bt_hs_on: bool,
    /// `btc8821a2ant_tdma_duration_adjust`.
    pub up: i64,
    pub dn: i64,
    pub m: i64,
    pub n: i64,
    pub wait_count: i64,
}

impl Default for Statics {
    fn default() -> Self {
        Self {
            pre_wifi_busy: true,
            pre_under_4way: true,
            pre_bt_hs_on: true,
            up: 0,
            dn: 0,
            m: 0,
            n: 0,
            wait_count: 0,
        }
    }
}

/// `btc8821a2ant_coex_table_with_type` rows (0x6c0, 0x6c4); 0x6c8 is
/// always `0xffffff` and 0x6cc `0x3`.
pub const COEX_TABLES: [(u32, u32); 18] = [
    (0x5555_5555, 0x5555_5555),
    (0x5555_5555, 0x5afa_5afa),
    (0x5ada_5ada, 0x5ada_5ada),
    (0xaaaa_aaaa, 0xaaaa_aaaa),
    (0xffff_ffff, 0xffff_ffff),
    (0x5fff_5fff, 0x5fff_5fff),
    (0x55ff_55ff, 0x5a5a_5a5a),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x5fff_5fff, 0xaaaa_aaaa),
    (0x5fff_5fff, 0x5ada_5ada),
    (0x55dd_55dd, 0xaaaa_aaaa),
    (0x5fdf_5fdf, 0x5fdb_5fdb),
    (0xfafa_fafa, 0xfafa_fafa),
];

/// Literal8821A source `ps_tdma` bytes, before no other modifiers.
pub const fn ps_tdma_bytes(on: bool, ty: u8) -> [u8; 5] {
    if !on {
        return if ty == 1 {
            [0, 0, 0, 0x48, 0]
        } else {
            [0, 0, 0, 0x40, 0]
        };
    }
    match ty {
        2 | 10 => [0xe3, 0x2d, 3, 0xf1, 0x90],
        3 | 11 => [0xe3, 0x1c, 3, 0xf1, 0x90],
        4 | 12 => [0xe3, 0x10, 3, 0xf1, 0x90],
        5 | 13 | 113 => [0xe3, 0x3c, 3, 0x70, 0x90],
        6 | 14 => [0xe3, 0x2d, 3, 0x70, 0x90],
        7 | 15 => [0xe3, 0x1c, 3, 0x70, 0x90],
        8 => [0xa3, 0x10, 3, 0x70, 0x90],
        16 => [0xe3, 0x10, 3, 0x70, 0x90],
        17 => [0xa3, 0x2f, 0x2f, 0x60, 0x90],
        18 => [0xe3, 5, 5, 0xe1, 0x90],
        19 => [0xe3, 0x25, 0x25, 0xe1, 0x90],
        20 => [0xe3, 0x25, 0x25, 0x60, 0x90],
        21 | 121 => [0xe3, 0x15, 3, 0x70, 0x90],
        22 | 122 => [0xe3, 0x35, 3, 0x71, 0x11],
        23 => [0xe3, 0x1e, 3, 0xf0, 0x14],
        24 | 124 => [0xd3, 0x3c, 3, 0x70, 0x50],
        25 => [0xe3, 0x14, 3, 0xf1, 0x90],
        26 => [0xe3, 0x30, 3, 0xf1, 0x90],
        101 | 105 | 171 => [0xd3, 0x3a, 3, 0x70, 0x50],
        102 | 106 | 110 | 114 => [0xd3, 0x2d, 3, 0x70, 0x50],
        103 | 107 | 111 | 115 => [0xd3, 0x1c, 3, 0x70, 0x50],
        104 | 108 | 112 | 116 => [0xd3, 0x10, 3, 0x70, 0x50],
        123 => [0xd3, 0x1c, 3, 0x70, 0x54],
        125 => [0xd3, 0x14, 3, 0x70, 0x50],
        126 => [0xd3, 0x30, 3, 0x70, 0x50],
        _ => [0xe3, 0x3c, 3, 0xf1, 0x90],
    }
}

/// One `if (cur_ps_tdma == a) ... else if ...` chain of
/// `btc8821a2ant_tdma_duration_adjust`: the first `(from, to)` matching
/// `cur_ps_tdma` runs `ps_tdma(NORMAL_EXEC, true, to)` and records `to`.
type Chain = &'static [(u8, u8)];

/// The `max_interval` / `tx_pause` arm of the adjusting branch: two
/// unconditional chains (normalising into the arm's type range), then the
/// `result == -1` chain and the `result == 1` chain.
#[derive(Debug)]
pub struct AdjustArm {
    pub pre: [Chain; 2],
    pub down: Chain,
    pub up: Chain,
}

/// `[max_interval - 1][tx_pause]`.
pub const ADJUST_ARMS: [[AdjustArm; 2]; 3] = [
    [
        AdjustArm {
            pre: [
                &[(5, 71), (6, 2), (7, 3), (8, 4)],
                &[(13, 9), (14, 10), (15, 11), (16, 12)],
            ],
            down: &[(71, 1), (1, 2), (2, 3), (3, 4), (9, 10), (10, 11), (11, 12)],
            up: &[(4, 3), (3, 2), (2, 1), (1, 71), (12, 11), (11, 10), (10, 9)],
        },
        AdjustArm {
            pre: [
                &[(71, 5), (1, 5), (2, 6), (3, 7), (4, 8)],
                &[(9, 13), (10, 14), (11, 15), (12, 16)],
            ],
            down: &[(5, 6), (6, 7), (7, 8), (13, 14), (14, 15), (15, 16)],
            up: &[(8, 7), (7, 6), (6, 5), (16, 15), (15, 14), (14, 13)],
        },
    ],
    [
        AdjustArm {
            pre: [
                &[(5, 2), (6, 2), (7, 3), (8, 4)],
                &[(13, 10), (14, 10), (15, 11), (16, 12)],
            ],
            down: &[(1, 2), (2, 3), (3, 4), (9, 10), (10, 11), (11, 12)],
            up: &[(4, 3), (3, 2), (2, 2), (12, 11), (11, 10), (10, 10)],
        },
        AdjustArm {
            pre: [
                &[(1, 6), (2, 6), (3, 7), (4, 8)],
                &[(9, 14), (10, 14), (11, 15), (12, 16)],
            ],
            down: &[(5, 6), (6, 7), (7, 8), (13, 14), (14, 15), (15, 16)],
            up: &[(8, 7), (7, 6), (6, 6), (16, 15), (15, 14), (14, 14)],
        },
    ],
    [
        AdjustArm {
            pre: [
                &[(5, 3), (6, 3), (7, 3), (8, 4)],
                &[(13, 11), (14, 11), (15, 11), (16, 12)],
            ],
            down: &[(1, 3), (2, 3), (3, 4), (9, 11), (10, 11), (11, 12)],
            up: &[(4, 3), (3, 3), (2, 3), (12, 11), (11, 11), (10, 11)],
        },
        AdjustArm {
            pre: [
                &[(1, 7), (2, 7), (3, 7), (4, 8)],
                &[(9, 15), (10, 15), (11, 15), (12, 16)],
            ],
            down: &[(5, 7), (6, 7), (7, 8), (13, 15), (14, 15), (15, 16)],
            up: &[(8, 7), (7, 7), (6, 7), (16, 15), (15, 15), (14, 15)],
        },
    ],
];

/// `btc8821a2ant_tdma_duration_adjust`'s first-run type.
pub const fn adjust_initial_type(sco_hid: bool, tx_pause: bool, max_interval: u8) -> u8 {
    let base = match (sco_hid, tx_pause) {
        (true, true) => 13,
        (true, false) => 9,
        (false, true) => 5,
        (false, false) => 1,
    };
    match max_interval {
        1 => base,
        2 => base + 1,
        _ => base + 2,
    }
}

/// `btc8821a2ant_bt_rssi_state` / `btc8821a2ant_wifi_rssi_state` over the
/// previous state.
pub fn rssi_state(pre: RssiState, rssi: i32, level_num: u8, thresh: u8, thresh1: u8) -> RssiState {
    let t = i32::from(thresh);
    let t1 = i32::from(thresh1);
    let low = matches!(pre, RssiState::Low | RssiState::StayLow);
    let medium = matches!(pre, RssiState::Medium | RssiState::StayMedium);
    match level_num {
        2 => {
            if low {
                if rssi >= t + RSSI_COEX_THRESH_TOL {
                    RssiState::High
                } else {
                    RssiState::StayLow
                }
            } else if rssi < t {
                RssiState::Low
            } else {
                RssiState::StayHigh
            }
        }
        3 => {
            if thresh > thresh1 {
                return pre;
            }
            if low {
                if rssi >= t + RSSI_COEX_THRESH_TOL {
                    RssiState::Medium
                } else {
                    RssiState::StayLow
                }
            } else if medium {
                if rssi >= t1 + RSSI_COEX_THRESH_TOL {
                    RssiState::High
                } else if rssi < t {
                    RssiState::Low
                } else {
                    RssiState::StayMedium
                }
            } else if rssi < t1 {
                RssiState::Medium
            } else {
                RssiState::StayHigh
            }
        }
        _ => pre,
    }
}

/// `btc8821a2ant_action_algorithm` over `bt_link_info`.
pub fn action_algorithm(l: &super::btc::BtLinkInfo, hs: bool) -> CoexAlgo {
    use CoexAlgo::*;
    if !l.bt_link_exist {
        return Undefined;
    }
    let n = [l.sco_exist, l.hid_exist, l.pan_exist, l.a2dp_exist]
        .iter()
        .filter(|v| **v)
        .count();
    if l.sco_exist {
        // Every SCO combination selects SCO, except the source's empty
        // all-four + HS branch, which retains UNDEFINED.
        return if n == 4 && hs { Undefined } else { Sco };
    }
    match (l.hid_exist, l.pan_exist, l.a2dp_exist) {
        (true, true, true) => {
            if hs {
                HidA2dp
            } else {
                HidA2dpPanEdr
            }
        }
        (true, false, true) => HidA2dp,
        (true, true, false) => {
            if hs {
                Hid
            } else {
                PanEdrHid
            }
        }
        (false, true, true) => {
            if hs {
                A2dpPanHs
            } else {
                PanEdrA2dp
            }
        }
        (true, false, false) => Hid,
        (false, true, false) => {
            if hs {
                PanHs
            } else {
                PanEdr
            }
        }
        (false, false, true) => A2dp,
        _ => Undefined,
    }
}

/// `halbtc8821a2ant` state.
#[derive(Clone, Debug, Default)]
pub struct B8821a2Ant {
    pub dm: CoexDm,
    pub sta: CoexSta,
    pub st: Statics,
}

type R = Result<(), Error>;

impl B8821a2Ant {
    pub fn new() -> Self {
        Self::default()
    }

    /// `btc8821a2ant_bt_rssi_state`.
    fn bt_rssi_state(&mut self, level_num: u8, thresh: u8, thresh1: u8) -> RssiState {
        let pre = self.sta.pre_bt_rssi_state;
        let s = rssi_state(pre, i32::from(self.sta.bt_rssi), level_num, thresh, thresh1);
        self.sta.pre_bt_rssi_state = s;
        s
    }

    /// `btc8821a2ant_wifi_rssi_state`.
    fn wifi_rssi_state<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        index: usize,
        level_num: u8,
        thresh: u8,
        thresh1: u8,
    ) -> RssiState {
        let pre = self.sta.pre_wifi_rssi_state[index];
        let s = rssi_state(pre, cx.wifi_rssi(), level_num, thresh, thresh1);
        self.sta.pre_wifi_rssi_state[index] = s;
        s
    }

    const fn wifi_thres(&self) -> u8 {
        WIFI_RSSI_COEXSWITCH_THRES
    }

    const fn bt_thres(&self) -> u8 {
        BT_RSSI_COEXSWITCH_THRES
    }

    /// `btc8821a2ant_limited_rx` (`force_exec` is unused in Linux).
    fn limited_rx<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        _force: bool,
        rej_ap_agg_pkt: bool,
        bt_ctrl_agg_buf_size: bool,
        agg_buf_size: u8,
    ) {
        cx.btc.bt_info.reject_agg_pkt = rej_ap_agg_pkt;
        cx.btc.bt_info.bt_ctrl_agg_buf_size = bt_ctrl_agg_buf_size;
        cx.btc.bt_info.agg_buf_size = agg_buf_size;
        cx.aggregation_check();
    }

    fn monitor_bt_ctr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let hp = cx.read_4byte(0x770)?;
        let lp = cx.read_4byte(0x774)?;
        self.sta.high_priority_tx = hp & 0xffff;
        self.sta.high_priority_rx = hp >> 16;
        self.sta.low_priority_tx = lp & 0xffff;
        self.sta.low_priority_rx = lp >> 16;
        cx.btc.bt_link_info.slave_role = self.sta.low_priority_rx >= 950
            && self.sta.low_priority_rx >= self.sta.low_priority_tx
            && !self.sta.under_ips;
        cx.write_1byte(0x76e, 0xc)
    }

    /// `btc8821a2ant_monitor_wifi_ctr`.
    fn monitor_wifi_ctr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if self.sta.under_ips {
            let s = &mut self.sta;
            s.crc_ok_cck = 0;
            s.crc_ok_11g = 0;
            s.crc_ok_11n = 0;
            s.crc_ok_11n_agg = 0;
            s.crc_err_cck = 0;
            s.crc_err_11g = 0;
            s.crc_err_11n = 0;
            s.crc_err_11n_agg = 0;
        } else {
            self.sta.crc_ok_cck = cx.read_4byte(0xf88)?;
            self.sta.crc_ok_11g = cx.read_2byte(0xf94)?.into();
            self.sta.crc_ok_11n = cx.read_2byte(0xf90)?.into();
            self.sta.crc_ok_11n_agg = cx.read_2byte(0xfb8)?.into();
            self.sta.crc_err_cck = cx.read_4byte(0xf84)?;
            self.sta.crc_err_11g = cx.read_2byte(0xf96)?.into();
            self.sta.crc_err_11n = cx.read_2byte(0xf92)?.into();
            self.sta.crc_err_11n_agg = cx.read_2byte(0xfba)?.into();
        }
        // Reset the CRC counters.
        cx.write_1byte_bitmask(0xf16, 0x1, 0x1)?;
        cx.write_1byte_bitmask(0xf16, 0x1, 0x0)
    }

    /// `btc8821a2ant_query_bt_info`.
    async fn query_bt_info<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.sta.c2h_bt_info_req_sent = true;
        cx.fill_h2c(H2C_BT_INFO, &[1]).await
    }

    /// `btc8821a2ant_is_wifi_status_changed`.
    fn is_wifi_status_changed<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> bool {
        let wifi = cx.btc.wifi;
        let bt_hs_on = cx.hs_operation();
        if wifi.connected() {
            if wifi.busy != self.st.pre_wifi_busy {
                self.st.pre_wifi_busy = wifi.busy;
                return true;
            }
            if wifi.in_4way != self.st.pre_under_4way {
                self.st.pre_under_4way = wifi.in_4way;
                return true;
            }
            if bt_hs_on != self.st.pre_bt_hs_on {
                self.st.pre_bt_hs_on = bt_hs_on;
                return true;
            }
            let tmp = self.wifi_thres();
            let s = self.wifi_rssi_state(cx, 3, 2, tmp, 0);
            if matches!(s, RssiState::High | RssiState::Low) {
                return true;
            }
        }
        false
    }

    /// `btc8821a2ant_update_bt_link_info`.
    fn update_bt_link_info<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) {
        let bt_hs_on = cx.hs_operation();
        let s = &self.sta;
        let l = &mut cx.btc.bt_link_info;
        l.bt_link_exist = s.bt_link_exist;
        l.sco_exist = s.sco_exist;
        l.a2dp_exist = s.a2dp_exist;
        l.pan_exist = s.pan_exist;
        l.hid_exist = s.hid_exist;
        if bt_hs_on {
            l.pan_exist = true;
            l.bt_link_exist = true;
        }
        l.sco_only = l.sco_exist && !l.a2dp_exist && !l.pan_exist && !l.hid_exist;
        l.a2dp_only = !l.sco_exist && l.a2dp_exist && !l.pan_exist && !l.hid_exist;
        l.pan_only = !l.sco_exist && !l.a2dp_exist && l.pan_exist && !l.hid_exist;
        l.hid_only = !l.sco_exist && !l.a2dp_exist && !l.pan_exist && l.hid_exist;
    }

    /// Source header fields are bool: every nonzero requested u8 level
    /// becomes1 before the firmware command and cached comparison.
    async fn dec_bt_pwr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, lvl: u8) -> R {
        self.dm.cur_dec_bt_pwr_lvl = lvl != 0;
        if !force && self.dm.pre_dec_bt_pwr_lvl == self.dm.cur_dec_bt_pwr_lvl {
            return Ok(());
        }
        cx.fill_h2c(H2C_DEC_BT_PWR, &[u8::from(self.dm.cur_dec_bt_pwr_lvl)])
            .await?;
        self.dm.pre_dec_bt_pwr_lvl = self.dm.cur_dec_bt_pwr_lvl;
        Ok(())
    }

    /// `btc8821a2ant_fw_dac_swing_lvl` → `set_fw_dac_swing_level`.
    async fn fw_dac_swing_lvl<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, lvl: u8) -> R {
        self.dm.cur_fw_dac_swing_lvl = lvl;
        if !force && self.dm.pre_fw_dac_swing_lvl == self.dm.cur_fw_dac_swing_lvl {
            return Ok(());
        }
        cx.fill_h2c(H2C_DAC_SWING, &[lvl]).await?;
        self.dm.pre_fw_dac_swing_lvl = self.dm.cur_fw_dac_swing_lvl;
        Ok(())
    }

    /// `btc8821a2ant_low_penalty_ra` → `btc8821a_set_penalty_txrate`.
    async fn low_penalty_ra<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, low: bool) -> R {
        self.dm.cur_low_penalty_ra = low;
        if !force && self.dm.pre_low_penalty_ra == self.dm.cur_low_penalty_ra {
            return Ok(());
        }
        // Normal rate except MCS7/6/5, OFDM54/48/36 retry penalty.
        let cmd = if low {
            [0x6, 0x1, 0x00, 0xf5, 0xa0, 0xa0]
        } else {
            [0x6, 0, 0, 0, 0, 0]
        };
        cx.fill_h2c(H2C_LOW_PENALTY_RA, &cmd).await?;
        self.dm.pre_low_penalty_ra = self.dm.cur_low_penalty_ra;
        Ok(())
    }

    /// `btc8821a2ant_dac_swing` → `set_sw_fulltime_dac_swing` →
    /// `set_dac_swing_reg` (0xc5b bits 5:1; 0x18 when off).
    async fn dac_swing<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        force: bool,
        on: bool,
        lvl: u32,
    ) -> R {
        self.dm.cur_dac_swing_on = on;
        self.dm.cur_dac_swing_lvl = lvl;
        if !force
            && self.dm.pre_dac_swing_on == self.dm.cur_dac_swing_on
            && self.dm.pre_dac_swing_lvl == self.dm.cur_dac_swing_lvl
        {
            return Ok(());
        }
        cx.hal.delay_ms(30).await;
        let val = if on { lvl as u8 } else { 0x18 };
        cx.write_1byte_bitmask(0xc5b, 0x3e, val)?;
        self.dm.pre_dac_swing_on = self.dm.cur_dac_swing_on;
        self.dm.pre_dac_swing_lvl = self.dm.cur_dac_swing_lvl;
        Ok(())
    }

    /// `btc8821a2ant_coex_table` → `set_coex_table`.
    fn coex_table<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        force: bool,
        v6c0: u32,
        v6c4: u32,
        v6c8: u32,
        v6cc: u8,
    ) -> R {
        let d = &mut self.dm;
        d.cur_val0x6c0 = v6c0;
        d.cur_val0x6c4 = v6c4;
        d.cur_val0x6c8 = v6c8;
        d.cur_val0x6cc = v6cc;
        if !force
            && d.pre_val0x6c0 == d.cur_val0x6c0
            && d.pre_val0x6c4 == d.cur_val0x6c4
            && d.pre_val0x6c8 == d.cur_val0x6c8
            && d.pre_val0x6cc == d.cur_val0x6cc
        {
            return Ok(());
        }
        cx.write_4byte(0x6c0, v6c0)?;
        cx.write_4byte(0x6c4, v6c4)?;
        cx.write_4byte(0x6c8, v6c8)?;
        cx.write_1byte(0x6cc, v6cc)?;
        let d = &mut self.dm;
        d.pre_val0x6c0 = d.cur_val0x6c0;
        d.pre_val0x6c4 = d.cur_val0x6c4;
        d.pre_val0x6c8 = d.cur_val0x6c8;
        d.pre_val0x6cc = d.cur_val0x6cc;
        Ok(())
    }

    fn coex_table_with_type<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, ty: u8) -> R {
        self.sta.coex_table_type = ty;
        if let Some(&(a, b)) = COEX_TABLES.get(usize::from(ty)) {
            self.coex_table(cx, force, a, b, 0xffffff, 3)?;
        }
        Ok(())
    }

    /// `btc8821a2ant_ignore_wlan_act` → `set_fw_ignore_wlan_act`.
    async fn ignore_wlan_act<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, on: bool) -> R {
        self.dm.cur_ignore_wlan_act = on;
        if !force && self.dm.pre_ignore_wlan_act == self.dm.cur_ignore_wlan_act {
            return Ok(());
        }
        cx.fill_h2c(H2C_IGNORE_WLAN_ACT, &[u8::from(on)]).await?;
        self.dm.pre_ignore_wlan_act = self.dm.cur_ignore_wlan_act;
        Ok(())
    }

    /// `btc8821a2ant_lps_rpwm` → `set_lps_rpwm`.
    fn lps_rpwm<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, lps: u8, rpwm: u8) {
        self.dm.cur_lps = lps;
        self.dm.cur_rpwm = rpwm;
        if !force && self.dm.pre_lps == self.dm.cur_lps && self.dm.pre_rpwm == self.dm.cur_rpwm {
            return;
        }
        // BTC_SET_U1_LPS_VAL / BTC_SET_U1_RPWM_VAL.
        cx.btc.bt_info.lps_val = lps;
        cx.btc.bt_info.rpwm_val = rpwm;
        self.dm.pre_lps = self.dm.cur_lps;
        self.dm.pre_rpwm = self.dm.cur_rpwm;
    }

    async fn set_fw_ps_tdma<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, b: [u8; 5]) -> R {
        self.dm.ps_tdma_para = b;
        cx.fill_h2c(H2C_TDMA, &b).await
    }

    async fn sw_mechanism<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, _shrink: bool, low: bool) -> R {
        self.low_penalty_ra(cx, NORMAL_EXEC, low).await
    }

    async fn sw_finish<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        low: bool,
        dac_on: bool,
        lvl: u32,
    ) -> R {
        self.sw_mechanism(cx, false, low).await?;
        self.dac_swing(cx, NORMAL_EXEC, dac_on, lvl).await
    }

    pub async fn set_ant_path<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        ant: u8,
        init: bool,
        _wifi_off: bool,
    ) -> R {
        if init {
            let value = (cx.read_4byte(0x4c)? & !(1 << 23)) | (1 << 24);
            cx.write_4byte(0x4c, value)?;
            cx.write_4byte(0x974, 0x3ff)?;
            let inverse = u8::from(cx.btc.board_info.btdm_ant_pos == BTC_ANTENNA_AT_MAIN_PORT);
            cx.fill_h2c(H2C_ANT_SEL, &[inverse, 1]).await?;
        }
        match ant {
            BTC_ANT_WIFI_AT_MAIN => cx.write_1byte_bitmask(0xcb7, 0x30, 1),
            BTC_ANT_WIFI_AT_AUX => cx.write_1byte_bitmask(0xcb7, 0x30, 2),
            _ => Ok(()),
        }
    }

    pub async fn ps_tdma<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        force: bool,
        on: bool,
        mut ty: u8,
    ) -> R {
        let wifi = self.wifi_rssi_state(cx, 1, 2, WIFI_RSSI_COEXSWITCH_THRES, 0);
        let bt = self.bt_rssi_state(2, BT_RSSI_COEXSWITCH_THRES, 0);
        if !(wifi.high() && bt.high()) && on {
            ty = ty.wrapping_add(100);
        }
        self.dm.cur_ps_tdma_on = on;
        self.dm.cur_ps_tdma = ty;
        if !force && self.dm.pre_ps_tdma_on == on && self.dm.pre_ps_tdma == ty {
            return Ok(());
        }
        self.set_fw_ps_tdma(cx, ps_tdma_bytes(on, ty)).await?;
        self.dm.pre_ps_tdma_on = self.dm.cur_ps_tdma_on;
        self.dm.pre_ps_tdma = self.dm.cur_ps_tdma;
        Ok(())
    }

    /// `btc8821a2ant_ps_tdma_check_for_power_save_state`.
    async fn ps_tdma_chk_pwr_save<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, new_ps_state: bool) -> R {
        let lps_mode = cx.lps_mode();
        // Already under LPS and leaving it, or not under LPS and entering
        // it: TDMA off first.
        if (lps_mode != 0) != new_ps_state {
            self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        }
        Ok(())
    }

    /// `btc8821a2ant_power_save_state`.
    async fn power_save_state<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        ps_type: PowerSave,
        lps_val: u8,
        rpwm_val: u8,
    ) -> R {
        match ps_type {
            PowerSave::WifiNative => {
                cx.disable_low_power(false);
                cx.normal_lps().await?;
                self.sta.force_lps_on = false;
            }
            PowerSave::LpsOn => {
                self.ps_tdma_chk_pwr_save(cx, true).await?;
                self.lps_rpwm(cx, NORMAL_EXEC, lps_val, rpwm_val);
                // Power save must be executed before PS TDMA.
                cx.disable_low_power(true);
                cx.enter_lps().await?;
                self.sta.force_lps_on = true;
            }
            PowerSave::LpsOff => {
                self.ps_tdma_chk_pwr_save(cx, false).await?;
                cx.leave_lps().await?;
                self.sta.force_lps_on = false;
            }
        }
        Ok(())
    }

    /// `btc8821a2ant_coex_alloff`.
    async fn coex_alloff<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        // Fw all off.
        self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
        // Sw all off.
        self.sw_finish(cx, false, false, 0x18).await?;
        // Source all-off has no RF register effect.
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)
    }

    /// `btc8821a2ant_init_coex_dm`.
    async fn init_coex_dm_inner<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        // Force to reset coex mechanism.
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
        self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
            .await?;
        self.ps_tdma(cx, FORCE_EXEC, false, 1).await?;
        self.fw_dac_swing_lvl(cx, FORCE_EXEC, 6).await?;
        self.dec_bt_pwr(cx, FORCE_EXEC, 0).await?;
        self.sw_finish(cx, false, false, 0x18).await?;
        Ok(())
    }

    async fn action_bt_inquiry<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        self.wifi_rssi_state(cx, 1, 2, WIFI_RSSI_COEXSWITCH_THRES, 0);
        self.bt_rssi_state(2, BT_RSSI_COEXSWITCH_THRES, 0);
        cx.disable_low_power(true);
        let w = cx.btc.wifi;
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        if w.scanning || w.linking || w.connected() {
            self.coex_table_with_type(cx, NORMAL_EXEC, 15)?;
            self.ps_tdma(cx, NORMAL_EXEC, true, 22).await?;
        } else {
            self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
            self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        }
        self.fw_dac_swing_lvl(cx, FORCE_EXEC, 6).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
        self.sw_finish(cx, false, false, 0x18).await
    }

    async fn action_wifi_link_process<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.coex_table_with_type(cx, NORMAL_EXEC, 15)?;
        self.ps_tdma(cx, NORMAL_EXEC, true, 22).await?;
        self.sw_finish(cx, false, false, 0x18).await?;
        let _ = cx.read_1byte(0x765)?;
        let _ = cx.read_1byte(0x76e)?;
        Ok(())
    }

    async fn action_wifi_idle_process<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
    ) -> Result<bool, Error> {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let w = self.wifi_rssi_state(cx, 1, 2, WIFI_RSSI_COEXSWITCH_THRES - 20, 0);
        self.bt_rssi_state(2, BT_RSSI_COEXSWITCH_THRES, 0);
        let _ap_num = cx.btc.wifi.ap_num;
        if (w.high() && self.sta.hid_exist && self.sta.a2dp_exist) || self.sta.pan_exist {
            self.dac_swing(cx, NORMAL_EXEC, true, 6).await?;
            self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
            self.sw_finish(cx, false, false, 0x18).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
            self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                .await?;
            self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
            return Ok(true);
        }
        self.dac_swing(cx, NORMAL_EXEC, true, 0x18).await?;
        Ok(false)
    }

    /// Source idle body; LPF-shrink/AGC parameters are inert in both
    /// SW wrappers, but the low-penalty then DAC operations remain ordered.
    async fn common_idle<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, dac_lvl: u8, _shrink: bool) -> R {
        self.limited_rx(cx, NORMAL_EXEC, false, false, 8);
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, dac_lvl).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
        self.sw_finish(cx, false, false, 0x18).await
    }

    /// `btc8821a2ant_is_common_action`.
    async fn is_common_action<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<bool, Error> {
        let bt_hs_on = cx.hs_operation();
        let w = cx.btc.wifi;
        if !w.connected() {
            cx.disable_low_power(false);
            self.common_idle(cx, 6, false).await?;
            return Ok(true);
        }
        match self.dm.bt_status {
            BtStatus::Idle => {
                cx.disable_low_power(false);
                self.common_idle(cx, 0xb, false).await?;
                Ok(true)
            }
            BtStatus::ConIdle => {
                cx.disable_low_power(true);
                if bt_hs_on {
                    return Ok(false);
                }
                self.common_idle(cx, 0xb, true).await?;
                Ok(true)
            }
            _ => {
                cx.disable_low_power(true);
                if w.busy {
                    Ok(false)
                } else {
                    self.action_wifi_idle_process(cx).await
                }
            }
        }
    }

    /// `ps_tdma(NORMAL_EXEC, true, ty)` and record it as the adjust type.
    async fn tdma_to<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: u8) -> R {
        self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
        self.dm.ps_tdma_du_adj_type = ty;
        Ok(())
    }

    /// One `if (cur_ps_tdma == ...) ... else if` chain.
    async fn chain<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, chain: Chain) -> R {
        let cur = self.dm.cur_ps_tdma;
        if let Some(&(_, to)) = chain.iter().find(|(from, _)| *from == cur) {
            self.tdma_to(cx, to).await?;
        }
        Ok(())
    }

    /// `btc8821a2ant_tdma_duration_adjust`.
    async fn tdma_duration_adjust<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        sco_hid: bool,
        tx_pause: bool,
        max_interval: u8,
    ) -> R {
        if self.dm.auto_tdma_adjust {
            self.dm.auto_tdma_adjust = false;
            let ty = adjust_initial_type(sco_hid, tx_pause, max_interval);
            self.tdma_to(cx, ty).await?;
            let st = &mut self.st;
            st.up = 0;
            st.dn = 0;
            st.m = 1;
            st.n = 3;
            st.wait_count = 0;
        } else {
            // Accquire the BT TRx retry count from BT_Info byte2.
            let retry_count = self.sta.bt_retry_cnt;
            let mut result = 0;
            let st = &mut self.st;
            st.wait_count += 1;
            if retry_count == 0 {
                // No retry in the last 2-second duration.
                st.up += 1;
                st.dn -= 1;
                if st.dn <= 0 {
                    st.dn = 0;
                }
                if st.up >= st.n {
                    st.wait_count = 0;
                    st.n = 3;
                    st.up = 0;
                    st.dn = 0;
                    result = 1;
                }
            } else if retry_count <= 3 {
                st.up -= 1;
                st.dn += 1;
                if st.up <= 0 {
                    st.up = 0;
                }
                if st.dn == 2 {
                    if st.wait_count <= 2 {
                        st.m += 1;
                    } else {
                        st.m = 1;
                    }
                    if st.m >= 20 {
                        st.m = 20;
                    }
                    st.n = 3 * st.m;
                    st.up = 0;
                    st.dn = 0;
                    st.wait_count = 0;
                    result = -1;
                }
            } else {
                if st.wait_count == 1 {
                    st.m += 1;
                } else {
                    st.m = 1;
                }
                if st.m >= 20 {
                    st.m = 20;
                }
                st.n = 3 * st.m;
                st.up = 0;
                st.dn = 0;
                st.wait_count = 0;
                result = -1;
            }
            if (1..=3).contains(&max_interval) {
                let arm = &ADJUST_ARMS[usize::from(max_interval - 1)][usize::from(tx_pause)];
                self.chain(cx, arm.pre[0]).await?;
                self.chain(cx, arm.pre[1]).await?;
                if result == -1 {
                    self.chain(cx, arm.down).await?;
                } else if result == 1 {
                    self.chain(cx, arm.up).await?;
                }
            }
        }
        // If the current PsTdma does not match the recorded one (scan,
        // DHCP...), restore it.
        if self.dm.cur_ps_tdma != self.dm.ps_tdma_du_adj_type {
            let w = cx.btc.wifi;
            if !w.scanning && !w.linking {
                let ty = self.dm.ps_tdma_du_adj_type;
                self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
            }
        }
        Ok(())
    }

    /// `dec_bt_pwr(2)` when BT RSSI is high, else `dec_bt_pwr(0)`.
    async fn dec_bt_pwr_by<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, bt: RssiState) -> R {
        let lvl = if bt.high() { 2 } else { 0 };
        self.dec_bt_pwr(cx, NORMAL_EXEC, lvl).await
    }

    /// The common `wifi_rssi_state(0, 2, 15, 0)`;
    /// `wifi_rssi_state(1, 2, wifi_thres, 0)`; `bt_rssi_state(2,
    /// bt_thres, 0)` prologue.
    fn rssi_prologue<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> (RssiState, RssiState) {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let t = self.wifi_thres();
        let w1 = self.wifi_rssi_state(cx, 1, 2, t, 0);
        let t = self.bt_thres();
        let bt = self.bt_rssi_state(2, t, 0);
        (w1, bt)
    }

    /// Native power save with `with_native` coex table when both RSSIs
    /// are high, else LPS 0x50 / RPWM 0x4 with `with_lps`.
    async fn table_and_ps<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        both_high: bool,
        with_native: u8,
        with_lps: u8,
    ) -> R {
        if both_high {
            self.coex_table_with_type(cx, NORMAL_EXEC, with_native)?;
            self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
                .await
        } else {
            self.coex_table_with_type(cx, NORMAL_EXEC, with_lps)?;
            self.power_save_state(cx, PowerSave::LpsOn, 0x50, 0x4).await
        }
    }

    async fn action_sco<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let bt = self.bt_rssi_state(2, 35, 0);
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 4).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, u8::from(bt.high()))
            .await?;
        let table = match cx.btc.wifi.bw() {
            WifiBw::Legacy => 2,
            WifiBw::Ht40 => 8,
            _ => {
                if cx.btc.bt_link_info.sco_only {
                    17
                } else {
                    12
                }
            }
        };
        self.coex_table_with_type(cx, NORMAL_EXEC, table)?;
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 0).await?;
        self.sw_finish(cx, true, true, 0x18).await
    }

    async fn action_hid<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let bt = self.bt_rssi_state(2, BT_RSSI_COEXSWITCH_THRES, 0);
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, u8::from(bt.high()))
            .await?;
        let table = if cx.btc.wifi.bw() == WifiBw::Legacy {
            7
        } else {
            2
        };
        self.coex_table_with_type(cx, NORMAL_EXEC, table)?;
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, true, 24).await?;
        self.sw_finish(cx, true, false, 0x18).await
    }

    async fn action_a2dp<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (wifi, bt) = self.rssi_prologue(cx);
        // Source ap_num is0 and never queried: its office branch is unreachable.
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        self.table_and_ps(cx, wifi.high() && bt.high(), 7, 13)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, true, 23).await?;
        self.sw_finish(cx, false, false, 0x18).await
    }

    async fn action_a2dp_pan_hs<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (wifi, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        self.table_and_ps(cx, wifi.high() && bt.high(), 7, 13)
            .await?;
        self.tdma_duration_adjust(cx, false, true, 2).await?;
        self.sw_finish(cx, false, false, 0x18).await
    }

    async fn action_pan_edr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (wifi, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, u8::from(bt.high()))
            .await?;
        self.table_and_ps(cx, wifi.high() && bt.high(), 10, 13)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, true, 26).await?;
        self.sw_finish(cx, false, false, 0x18).await
    }

    async fn action_pan_hs<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (_, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 7)?;
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        self.sw_finish(cx, false, false, 0x18).await
    }

    async fn action_pan_edr_a2dp<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (wifi, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        if wifi.high() && bt.high() {
            self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                .await?;
        } else {
            self.power_save_state(cx, PowerSave::LpsOn, 0x50, 4).await?;
        }
        if bt.high() {
            self.coex_table_with_type(cx, NORMAL_EXEC, 12)?;
            let ht40 = cx.btc.wifi.bw() == WifiBw::Ht40;
            self.tdma_duration_adjust(cx, false, ht40, 3).await?;
        } else {
            self.coex_table_with_type(cx, NORMAL_EXEC, 13)?;
            self.tdma_duration_adjust(cx, false, true, 3).await?;
        }
        self.sw_finish(cx, false, false, 0x18).await
    }

    async fn action_pan_edr_hid<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let bt = self.bt_rssi_state(2, BT_RSSI_COEXSWITCH_THRES, 0);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, u8::from(bt.high()))
            .await?;
        // Direct source table does not update coex_table_type, alter RF,
        // limited RX, or native/LPS state.
        self.coex_table(cx, NORMAL_EXEC, 0x55ff55ff, 0x5a5f5a5f, 0xffff, 3)?;
        let dac = if cx.btc.wifi.bw() == WifiBw::Ht40 {
            3
        } else {
            6
        };
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, dac).await?;
        self.ps_tdma(cx, NORMAL_EXEC, true, if bt.high() { 10 } else { 14 })
            .await?;
        self.sw_finish(cx, true, false, 0x18).await
    }

    async fn action_hid_a2dp_pan_edr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (wifi, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        self.table_and_ps(cx, wifi.high() && bt.high(), 7, 14)
            .await?;
        let tx_pause = !bt.high() || cx.btc.wifi.bw() == WifiBw::Ht40;
        self.tdma_duration_adjust(cx, true, tx_pause, 3).await?;
        self.sw_finish(cx, true, false, 0x18).await
    }

    async fn action_hid_a2dp<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        self.wifi_rssi_state(cx, 1, 2, WIFI_RSSI_COEXSWITCH_THRES, 0);
        // The reversed source thresholds deliberately retain the previous state.
        let bt = self.bt_rssi_state(3, BT_RSSI_COEXSWITCH_THRES, 37);
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, true, 5);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        let bw = cx.btc.wifi.bw();
        let level = if bw == WifiBw::Legacy {
            if bt.high() || bt.medium() {
                2
            } else {
                0
            }
        } else if bt.high() {
            if cx.btc.wifi.ap_num < 10 {
                4
            } else {
                2
            }
        } else if bt.medium() {
            2
        } else {
            0
        };
        self.dec_bt_pwr(cx, NORMAL_EXEC, level).await?;
        if bw == WifiBw::Legacy {
            self.coex_table_with_type(cx, NORMAL_EXEC, 7)?;
            self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                .await?;
        } else {
            self.coex_table_with_type(cx, NORMAL_EXEC, 14)?;
            self.power_save_state(cx, PowerSave::LpsOn, 0x50, 4).await?;
        }
        self.ps_tdma(cx, NORMAL_EXEC, true, 23).await?;
        self.sw_finish(cx, true, false, 0x18).await
    }

    /// `btc8821a2ant_action_wifi_multi_port`.
    async fn action_wifi_multi_port<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
        self.sw_finish(cx, false, false, 0x18).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
        self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 1).await
    }

    /// `btc8821a2ant_run_coexist_mechanism`.
    async fn run_coexist_mechanism<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if cx.btc.manual_control {
            return Ok(());
        }
        if cx.btc.wifi.under_5g {
            self.coex_alloff(cx).await?;
            return self.ignore_wlan_act(cx, NORMAL_EXEC, true).await;
        }
        if self.sta.under_ips {
            return Ok(());
        }
        let algorithm = action_algorithm(&cx.btc.bt_link_info, cx.hs_operation());
        if self.sta.c2h_bt_inquiry_page && algorithm != CoexAlgo::PanHs {
            return self.action_bt_inquiry(cx).await;
        }
        let w = cx.btc.wifi;
        // BTC_GET_BL_WIFI_ROAM is the LINKING state too.
        if w.scanning || w.linking {
            return self.action_wifi_link_process(cx).await;
        }
        let link_status = w.link_status();
        let num_of_wifi_link = link_status >> 16;
        if num_of_wifi_link >= 2 || link_status & WIFI_P2P_GO_CONNECTED != 0 {
            cx.btc.bt_info.miracast_plus_bt = cx.btc.bt_link_info.bt_link_exist;
            return self.action_wifi_multi_port(cx).await;
        }
        cx.btc.bt_info.miracast_plus_bt = false;
        self.dm.cur_algorithm = algorithm;
        if self.is_common_action(cx).await? {
            self.dm.auto_tdma_adjust = true;
            return Ok(());
        }
        if self.dm.cur_algorithm != self.dm.pre_algorithm {
            self.dm.auto_tdma_adjust = false;
        }
        match self.dm.cur_algorithm {
            CoexAlgo::Sco => self.action_sco(cx).await?,
            CoexAlgo::Hid => self.action_hid(cx).await?,
            CoexAlgo::A2dp => self.action_a2dp(cx).await?,
            CoexAlgo::A2dpPanHs => self.action_a2dp_pan_hs(cx).await?,
            CoexAlgo::PanEdr => self.action_pan_edr(cx).await?,
            CoexAlgo::PanHs => self.action_pan_hs(cx).await?,
            CoexAlgo::PanEdrA2dp => self.action_pan_edr_a2dp(cx).await?,
            CoexAlgo::PanEdrHid => self.action_pan_edr_hid(cx).await?,
            CoexAlgo::HidA2dpPanEdr => self.action_hid_a2dp_pan_edr(cx).await?,
            CoexAlgo::HidA2dp => self.action_hid_a2dp(cx).await?,
            _ => self.coex_alloff(cx).await?,
        }
        self.dm.pre_algorithm = self.dm.cur_algorithm;
        Ok(())
    }

    async fn wifioff_hwcfg<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        cx.write_1byte(0x76e, 4)?;
        cx.set_rf_reg(BTC_RF_A, 1, 0xfffff, 0x780).await?;
        if cx.btc.wifi.fw_ver() >= 0x180000 {
            cx.fill_h2c(H2C_BT_CALIBRATION, &[1]).await
        } else {
            cx.write_1byte(0x765, 0x18)
        }
    }

    /// `ex_btc8821a2ant_init_hwconfig`.
    async fn init_hwconfig_inner<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        // Backup rf 0x1e value.
        self.dm.bt_rf0x1e_backup = cx.get_rf_reg(BTC_RF_A, 0x1e, 0xfffff).await?;
        // 0x790[5:0] = 0x5.
        let v = cx.read_1byte(0x790)?;
        cx.write_1byte(0x790, (v & 0xc0) | 0x5)?;
        // Antenna config.
        self.set_ant_path(cx, BTC_ANT_WIFI_AT_MAIN, true, false)
            .await?;
        self.sta.dis_ver_info_cnt = 0;
        // PTA parameter.
        self.coex_table_with_type(cx, FORCE_EXEC, 0)?;
        // Enable counter statistics: 0x76e[3] = 1, WLAN_Act control by PTA.
        cx.write_1byte(0x76e, 0x4)?;
        cx.write_1byte(0x778, 0x3)?;
        cx.write_1byte_bitmask(0x40, 0x20, 0x1)?;
        Ok(())
    }

    async fn media_status<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Media) -> R {
        let mut h2c = [0u8; 3];
        let channel = cx.btc.wifi.central_chnl();
        if ty == Media::Connect && channel <= 14 {
            h2c = [1, channel, 0x30];
        }
        // ap_num is initialized0 and never loaded in this source handler.
        self.dm.wifi_chnl_info = h2c;
        cx.fill_h2c(H2C_WIFI_CHNL, &h2c).await
    }
}

impl Algorithm for B8821a2Ant {
    // No8821A two-antenna power-on handler exists in the source dispatch.
    async fn power_on_setting<H: Hal>(&mut self, _cx: &mut Ctx<'_, H>) -> R {
        Ok(())
    }

    /// `ex_btc8821a2ant_pre_load_firmware`.
    async fn pre_load_firmware<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        // Set antenna control by WL by default: BIT2.
        let mut u8tmp = 0x4u8;
        if cx.btc.chip_interface == ChipInterface::Usb {
            u8tmp |= 0x1;
            return cx.write_local_reg_1byte(0xfe08, u8tmp);
        }
        if cx.btc.board_info.single_ant_path == 1 {
            u8tmp |= 0x1;
        }
        match cx.btc.chip_interface {
            ChipInterface::Pci => cx.write_local_reg_1byte(0x384, u8tmp),
            ChipInterface::Sdio => cx.write_local_reg_1byte(0x60, u8tmp),
            _ => Ok(()),
        }
    }

    /// `ex_btc8821a2ant_init_hwconfig` (the 2-antenna handler takes no
    /// `wifi_only`).
    async fn init_hw_config<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, _wifi_only: bool) -> R {
        self.init_hwconfig_inner(cx).await
    }

    /// `ex_btc8821a2ant_init_coex_dm`.
    async fn init_coex_dm<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.init_coex_dm_inner(cx).await
    }

    /// `ex_btc8821a2ant_ips_notify`.
    async fn ips_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Ips) -> R {
        match ty {
            Ips::Enter => {
                self.sta.under_ips = true;
                self.wifioff_hwcfg(cx).await?;
                self.ignore_wlan_act(cx, FORCE_EXEC, true).await?;
                self.coex_alloff(cx).await
            }
            Ips::Leave => {
                self.sta.under_ips = false;
                self.init_hwconfig_inner(cx).await?;
                self.init_coex_dm_inner(cx).await?;
                self.query_bt_info(cx).await
            }
        }
    }

    /// `ex_btc8821a2ant_lps_notify`.
    async fn lps_notify<H: Hal>(&mut self, _cx: &mut Ctx<'_, H>, ty: Lps) -> R {
        self.sta.under_lps = ty == Lps::Enable;
        Ok(())
    }

    // Source handler only logs, even for ScanStart.
    async fn scan_notify<H: Hal>(&mut self, _cx: &mut Ctx<'_, H>, _ty: Scan) -> R {
        Ok(())
    }

    async fn connect_notify<H: Hal>(&mut self, _cx: &mut Ctx<'_, H>, _ty: Associate) -> R {
        Ok(())
    }

    /// `ex_btc8821a2ant_media_status_notify`.
    async fn media_status_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Media) -> R {
        self.media_status(cx, ty).await
    }

    async fn special_packet_notify<H: Hal>(&mut self, _cx: &mut Ctx<'_, H>, _ty: Packet) -> R {
        Ok(())
    }

    async fn bt_info_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, buf: &[u8]) -> R {
        self.sta.c2h_bt_info_req_sent = false;
        let under_5g = cx.btc.wifi.under_5g;
        let connected = cx.btc.wifi.connected();
        let mut source = usize::from(buf.first().copied().unwrap_or(0) & 0xf);
        if source >= BT_INFO_SRC_MAX {
            source = BT_INFO_SRC_WIFI_FW;
        }
        let n = buf.len().min(10);
        self.sta.bt_info_c2h_cnt[source] = self.sta.bt_info_c2h_cnt[source].wrapping_add(1);
        // Bound the source's unchecked ten-byte row, preserving prior short tails.
        self.sta.bt_info_c2h[source][..n].copy_from_slice(&buf[..n]);
        let info = buf.get(1).copied().unwrap_or(0);
        if cx.btc.manual_control {
            return Ok(());
        }
        if source != BT_INFO_SRC_WIFI_FW {
            let row = self.sta.bt_info_c2h[source];
            self.sta.bt_retry_cnt = row[2] & 0xf;
            self.sta.bt_rssi = row[3].wrapping_mul(2).wrapping_add(10);
            self.sta.bt_info_ext = row[4];
            self.sta.bt_tx_rx_mask = row[2] & 0x40 != 0;
            cx.btc.bt_info.bt_tx_rx_mask = self.sta.bt_tx_rx_mask;
            if self.sta.bt_tx_rx_mask {
                cx.set_bt_reg(BtReg::Rf, 0x3c, 1).await?;
            }
            if self.sta.bt_info_ext & 2 != 0 {
                self.media_status(
                    cx,
                    if connected {
                        Media::Connect
                    } else {
                        Media::Disconnect
                    },
                )
                .await?;
            }
            if !under_5g {
                if self.sta.bt_info_ext & 8 != 0 {
                    if connected {
                        self.ignore_wlan_act(cx, FORCE_EXEC, false).await?;
                    }
                } else if !connected {
                    self.ignore_wlan_act(cx, FORCE_EXEC, true).await?;
                }
            }
        }
        let s = &mut self.sta;
        s.c2h_bt_inquiry_page = info & BT_INFO_B_INQ_PAGE != 0;
        s.bt_link_exist = info & BT_INFO_B_CONNECTION != 0;
        s.pan_exist = s.bt_link_exist && info & BT_INFO_B_FTP != 0;
        s.a2dp_exist = s.bt_link_exist && info & BT_INFO_B_A2DP != 0;
        s.hid_exist = s.bt_link_exist && info & BT_INFO_B_HID != 0;
        s.sco_exist = s.bt_link_exist && info & BT_INFO_B_SCO_ESCO != 0;
        if s.bt_link_exist
            && !s.hid_exist
            && !s.c2h_bt_inquiry_page
            && !s.sco_exist
            && s.high_priority_tx.wrapping_add(s.high_priority_rx) >= 160
        {
            s.hid_exist = true;
        }
        self.update_bt_link_info(cx);
        self.dm.bt_status = if info & BT_INFO_B_CONNECTION == 0 {
            BtStatus::Idle
        } else if info == BT_INFO_B_CONNECTION {
            BtStatus::ConIdle
        } else if info & (BT_INFO_B_SCO_ESCO | BT_INFO_B_SCO_BUSY) != 0 {
            BtStatus::ScoBusy
        } else if info & BT_INFO_B_ACL_BUSY != 0 {
            BtStatus::AclBusy
        } else {
            BtStatus::Max
        };
        let busy = matches!(
            self.dm.bt_status,
            BtStatus::AclBusy | BtStatus::ScoBusy | BtStatus::AclScoBusy
        );
        cx.btc.bt_info.bt_busy = busy;
        self.dm.limited_dig = busy;
        cx.btc.bt_info.limited_dig = busy;
        self.run_coexist_mechanism(cx).await
    }

    /// `ex_btc8821a2ant_halt_notify`.
    async fn halt_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifioff_hwcfg(cx).await?;
        self.ignore_wlan_act(cx, FORCE_EXEC, true).await?;
        self.media_status(cx, Media::Disconnect).await
    }

    async fn pnp_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, state: Pnp) -> R {
        if state == Pnp::WakeUp {
            self.init_hwconfig_inner(cx).await?;
            self.init_coex_dm_inner(cx).await?;
            self.query_bt_info(cx).await?;
        }
        Ok(())
    }

    async fn periodical<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if self.sta.dis_ver_info_cnt <= 5 {
            self.sta.dis_ver_info_cnt += 1;
            if self.sta.dis_ver_info_cnt == 3 {
                self.set_ant_path(cx, BTC_ANT_WIFI_AT_MAIN, false, false)
                    .await?;
            }
        }
        if cx.btc.auto_report_2ant {
            self.query_bt_info(cx).await
        } else {
            self.monitor_bt_ctr(cx)?;
            self.monitor_wifi_ctr(cx)?;
            if self.is_wifi_status_changed(cx) || self.dm.auto_tdma_adjust {
                self.run_coexist_mechanism(cx).await?;
            }
            Ok(())
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "b8821a2ant_tests.rs"]
mod tests;
