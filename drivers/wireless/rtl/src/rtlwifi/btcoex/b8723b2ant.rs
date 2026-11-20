// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723B dual-antenna BT coexistence: `btcoexist/halbtc8723b2ant.{c,h}`
//! (Linux 7.3-rc4, `glcoex_ver_8723b_2ant = 0x3f`, 20131113).
//!
//! The Linux file-scope `coex_dm` / `coex_sta` and the function-local
//! `static`s (`btc8723b2ant_is_wifi_status_changed`'s previous
//! busy / 4-way / HS flags and `btc8723b2ant_tdma_duration_adjust`'s
//! `up/dn/m/n/wait_count`) are per-instance fields of [`B8723b2Ant`].
//! Every handler is the Linux one in order, including the register reads
//! Linux only logs (they are real bus reads) and the RSSI-state updates
//! whose results are discarded (they move `pre_*_rssi_state`).
//! `ex_btc8723b2ant_display_coex_info` (debugfs) is not carried.
//!
//! What the glue makes constant on rtlwifi (and therefore here):
//! `BTC_GET_BL_HS_OPERATION` false, `BTC_GET_BL_EXT_SWITCH` false,
//! `BTC_GET_BL_WIFI_IS_IN_MP_MODE` false;
//! `BTC_SET_ACT_ANTPOSREGRISTRY_CTRL` has no rtlwifi handler.
//! `switch_thres_offset` is never assigned in Linux and stays 0.
//!
//! Difference from Linux: `ex_btc8723b2ant_bt_info_notify` copies at most
//! ten bytes (the `bt_info_c2h` row size) where Linux writes `length`
//! bytes into the row unchecked; a missing byte reads as 0.

#![allow(dead_code)]

use super::btc::{
    Algorithm, Associate, ChipInterface, Ctx, Hal, Ips, Lps, Media, Packet, Pnp, PowerSave,
    RssiState, Scan, WifiBw, BTC_ANTENNA_AT_AUX_PORT, BTC_ANTENNA_AT_MAIN_PORT,
    BTC_ANT_WIFI_AT_AUX, BTC_ANT_WIFI_AT_MAIN, BTC_RF_A, FORCE_EXEC, NORMAL_EXEC,
    WIFI_P2P_GO_CONNECTED,
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

/// `BTC_RSSI_COEX_THRESH_TOL_8723B_2ANT`.
pub const RSSI_COEX_THRESH_TOL: i32 = 2;
/// `BT_8723B_2ANT_WIFI_RSSI_COEXSWITCH_THRES`.
pub const WIFI_RSSI_COEXSWITCH_THRES: u8 = 42;
/// `BT_8723B_2ANT_BT_RSSI_COEXSWITCH_THRES`.
pub const BT_RSSI_COEXSWITCH_THRES: u8 = 46;

/// `enum BT_INFO_SRC_8723B_2ANT`.
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

/// `enum BT_8723B_2ANT_BT_STATUS`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BtStatus {
    #[default]
    NonConnectedIdle = 0,
    ConnectedIdle = 1,
    InqPage = 2,
    AclBusy = 3,
    ScoBusy = 4,
    AclScoBusy = 5,
    Max = 6,
}

/// `enum BT_8723B_2ANT_COEX_ALGO`.
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

/// `struct coex_dm_8723b_2ant`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoexDm {
    pub pre_dec_bt_pwr_lvl: u8,
    pub cur_dec_bt_pwr_lvl: u8,
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
    pub is_switch_to_1dot5_ant: bool,
    pub switch_thres_offset: u8,
}

/// `struct coex_sta_8723b_2ant`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoexSta {
    pub bt_link_exist: bool,
    pub sco_exist: bool,
    pub a2dp_exist: bool,
    pub hid_exist: bool,
    pub pan_exist: bool,
    pub bt_abnormal_scan: bool,
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
    pub c2h_bt_remote_name_req: bool,
    pub bt_retry_cnt: u8,
    pub bt_info_ext: u8,
    pub pop_event_cnt: u32,
    pub scan_ap_num: u8,
    pub crc_ok_cck: u32,
    pub crc_ok_11g: u32,
    pub crc_ok_11n: u32,
    pub crc_ok_11n_agg: u32,
    pub crc_err_cck: u32,
    pub crc_err_11g: u32,
    pub crc_err_11n: u32,
    pub crc_err_11n_agg: u32,
    pub force_lps_on: bool,
    pub dis_ver_info_cnt: u8,
    pub a2dp_bit_pool: u8,
}

/// The Linux function-local statics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statics {
    /// `btc8723b2ant_is_wifi_status_changed`.
    pub pre_wifi_busy: bool,
    pub pre_under_4way: bool,
    pub pre_bt_hs_on: bool,
    /// `btc8723b2ant_tdma_duration_adjust`.
    pub up: i32,
    pub dn: i32,
    pub m: i32,
    pub n: i32,
    pub wait_count: i32,
}

/// `btc8723b2ant_coex_table_with_type` rows (0x6c0, 0x6c4); 0x6c8 is
/// always `0xffffff` and 0x6cc `0x3`.
pub const COEX_TABLES: [(u32, u32); 16] = [
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
];

/// `btc8723b2ant_ps_tdma`'s `wifi_duration_adjust` over
/// `scan_ap_num` / `a2dp_bit_pool`.
pub const fn wifi_duration_adjust(scan_ap_num: u8, a2dp_bit_pool: u8) -> i8 {
    if a2dp_bit_pool >= 45 {
        -15
    } else if a2dp_bit_pool >= 35 {
        -10
    } else if scan_ap_num <= 5 {
        5
    } else if scan_ap_num <= 20 {
        0
    } else if scan_ap_num <= 40 {
        -5
    } else {
        -10
    }
}

/// `btc8723b2ant_ps_tdma`'s byte selection for the (possibly 1.5-antenna
/// `+ 100`) type before `set_fw_ps_tdma`'s A2DP+HID byte-5 bit. `adj` is
/// [`wifi_duration_adjust`]; `b4` is the `slave_role && a2dp_exist`
/// `tdma_byte4_modify` bit.
pub const fn ps_tdma_bytes(turn_on: bool, ty: u8, adj: i8, b4: u8) -> [u8; 5] {
    const fn d(base: u8, adj: i8) -> u8 {
        base.wrapping_add(adj as u8)
    }
    if !turn_on {
        return match ty {
            1 => [0, 0, 0, 0x48, 0],
            _ => [0, 0, 0, 0x40, 0],
        };
    }
    match ty {
        2 | 10 => [0xe3, 0x2d, 0x03, 0xf1, 0x90 | b4],
        3 | 11 => [0xe3, 0x1c, 0x03, 0xf1, 0x90 | b4],
        4 | 12 => [0xe3, 0x10, 0x03, 0xf1, 0x90 | b4],
        5 | 13 => [0xe3, 0x3c, 0x03, 0x70, 0x90 | b4],
        6 | 14 => [0xe3, 0x2d, 0x03, 0x70, 0x90 | b4],
        7 | 15 => [0xe3, 0x1c, 0x03, 0x70, 0x90 | b4],
        8 => [0xa3, 0x10, 0x03, 0x70, 0x90 | b4],
        9 => [0xe3, d(0x3c, adj), 0x03, 0xf1, 0x90 | b4],
        16 => [0xe3, 0x10, 0x03, 0x70, 0x90 | b4],
        17 => [0xa3, 0x2f, 0x2f, 0x60, 0x90],
        18 => [0xe3, 0x05, 0x05, 0xe1, 0x90],
        19 => [0xe3, 0x25, 0x25, 0xe1, 0x90],
        20 => [0xe3, 0x25, 0x25, 0x60, 0x90],
        21 => [0xe3, 0x15, 0x03, 0x70, 0x90],
        23 | 123 => [0xe3, 0x35, 0x03, 0x71, 0x10],
        71 => [0xe3, d(0x3c, adj), 0x03, 0xf1, 0x90],
        101 | 105 | 113 | 171 => [0xd3, d(0x3a, adj), 0x03, 0x70, 0x50 | b4],
        102 | 106 | 110 | 114 => [0xd3, d(0x2d, adj), 0x03, 0x70, 0x50 | b4],
        103 | 107 | 111 | 115 => [0xd3, 0x1c, 0x03, 0x70, 0x50 | b4],
        104 | 108 | 112 | 116 => [0xd3, 0x10, 0x03, 0x70, 0x50 | b4],
        109 => [0xe3, 0x3c, 0x03, 0xf1, 0x90 | b4],
        121 => [0xe3, 0x15, 0x03, 0x70, 0x90 | b4],
        22 | 122 => [0xe3, 0x35, 0x03, 0x71, 0x11],
        // case 1 and default.
        _ => [0xe3, 0x3c, 0x03, 0xf1, 0x90 | b4],
    }
}

/// One `if (cur_ps_tdma == a) ... else if ...` chain of
/// `btc8723b2ant_tdma_duration_adjust`: the first `(from, to)` matching
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

/// `btc8723b2ant_tdma_duration_adjust`'s first-run type.
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

/// `btc8723b2ant_bt_rssi_state` / `btc8723b2ant_wifi_rssi_state` over the
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

/// `btc8723b2ant_action_algorithm` over `bt_link_info`.
pub fn action_algorithm(l: &super::btc::BtLinkInfo, bt_hs_on: bool) -> CoexAlgo {
    use CoexAlgo::*;
    if !l.bt_link_exist {
        return Undefined;
    }
    let n = [l.sco_exist, l.hid_exist, l.pan_exist, l.a2dp_exist]
        .iter()
        .filter(|x| **x)
        .count();
    match n {
        1 => {
            if l.sco_exist {
                Sco
            } else if l.hid_exist {
                Hid
            } else if l.a2dp_exist {
                A2dp
            } else if l.pan_exist {
                if bt_hs_on {
                    PanHs
                } else {
                    PanEdr
                }
            } else {
                Undefined
            }
        }
        2 => {
            if l.sco_exist {
                if l.hid_exist || l.a2dp_exist {
                    PanEdrHid
                } else if l.pan_exist {
                    if bt_hs_on {
                        Sco
                    } else {
                        PanEdrHid
                    }
                } else {
                    Undefined
                }
            } else if l.hid_exist && l.a2dp_exist {
                HidA2dp
            } else if l.hid_exist && l.pan_exist {
                if bt_hs_on {
                    Hid
                } else {
                    PanEdrHid
                }
            } else if l.pan_exist && l.a2dp_exist {
                if bt_hs_on {
                    A2dpPanHs
                } else {
                    PanEdrA2dp
                }
            } else {
                Undefined
            }
        }
        3 => {
            if l.sco_exist {
                // Two of HID / PAN / A2DP exist: every Linux arm (HS or
                // not) picks PANEDR_HID.
                PanEdrHid
            } else if l.hid_exist && l.pan_exist && l.a2dp_exist {
                if bt_hs_on {
                    HidA2dp
                } else {
                    HidA2dpPanEdr
                }
            } else {
                Undefined
            }
        }
        // `num_of_diff_profile >= 3` with all four.
        _ => {
            if l.sco_exist && l.hid_exist && l.pan_exist && l.a2dp_exist && !bt_hs_on {
                PanEdrHid
            } else {
                Undefined
            }
        }
    }
}

/// `halbtc8723b2ant` state.
#[derive(Clone, Debug, Default)]
pub struct B8723b2Ant {
    pub dm: CoexDm,
    pub sta: CoexSta,
    pub st: Statics,
}

type R = Result<(), Error>;

impl B8723b2Ant {
    pub fn new() -> Self {
        Self::default()
    }

    /// `btc8723b2ant_bt_rssi_state`.
    fn bt_rssi_state(&mut self, level_num: u8, thresh: u8, thresh1: u8) -> RssiState {
        let pre = self.sta.pre_bt_rssi_state;
        let s = rssi_state(pre, i32::from(self.sta.bt_rssi), level_num, thresh, thresh1);
        self.sta.pre_bt_rssi_state = s;
        s
    }

    /// `btc8723b2ant_wifi_rssi_state`.
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

    /// `WIFI_RSSI_COEXSWITCH_THRES - switch_thres_offset`.
    const fn wifi_thres(&self) -> u8 {
        WIFI_RSSI_COEXSWITCH_THRES.wrapping_sub(self.dm.switch_thres_offset)
    }

    /// `BT_RSSI_COEXSWITCH_THRES - switch_thres_offset`.
    const fn bt_thres(&self) -> u8 {
        BT_RSSI_COEXSWITCH_THRES.wrapping_sub(self.dm.switch_thres_offset)
    }

    /// `btc8723b2ant_limited_rx` (`force_exec` is unused in Linux).
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

    /// `btc8723b2ant_monitor_bt_ctr`.
    fn monitor_bt_ctr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let hp = cx.read_4byte(0x770)?;
        let lp = cx.read_4byte(0x774)?;
        let s = &mut self.sta;
        s.high_priority_tx = hp & 0xffff;
        s.high_priority_rx = hp >> 16;
        s.low_priority_tx = lp & 0xffff;
        s.low_priority_rx = lp >> 16;
        if s.low_priority_tx > 1050 && !s.c2h_bt_inquiry_page {
            s.pop_event_cnt = s.pop_event_cnt.wrapping_add(1);
        }
        cx.btc.bt_link_info.slave_role =
            s.low_priority_rx >= 950 && s.low_priority_rx >= s.low_priority_tx && !s.under_ips;
        // Reset the counters.
        cx.write_1byte(0x76e, 0xc)
    }

    /// `btc8723b2ant_monitor_wifi_ctr`.
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

    /// `btc8723b2ant_query_bt_info`.
    async fn query_bt_info<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.sta.c2h_bt_info_req_sent = true;
        cx.fill_h2c(H2C_BT_INFO, &[1]).await
    }

    /// `btc8723b2ant_is_wifi_status_changed`.
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
            let s = self.wifi_rssi_state(cx, 0, 2, tmp, 0);
            if matches!(s, RssiState::High | RssiState::Low) {
                return true;
            }
        }
        false
    }

    /// `btc8723b2ant_update_bt_link_info`.
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

    /// `btc8723b2ant_dec_bt_pwr` → `set_fw_dec_bt_pwr`.
    async fn dec_bt_pwr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, lvl: u8) -> R {
        self.dm.cur_dec_bt_pwr_lvl = lvl;
        if !force && self.dm.pre_dec_bt_pwr_lvl == self.dm.cur_dec_bt_pwr_lvl {
            return Ok(());
        }
        cx.fill_h2c(H2C_DEC_BT_PWR, &[lvl]).await?;
        self.dm.pre_dec_bt_pwr_lvl = self.dm.cur_dec_bt_pwr_lvl;
        Ok(())
    }

    /// `btc8723b2ant_bt_auto_report` → `halbtc8723b2ant_set_bt_auto_report`.
    async fn bt_auto_report<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, on: bool) -> R {
        self.dm.cur_bt_auto_report = on;
        if !force && self.dm.pre_bt_auto_report == self.dm.cur_bt_auto_report {
            return Ok(());
        }
        cx.fill_h2c(H2C_BT_AUTO_REPORT, &[u8::from(on)]).await?;
        self.dm.pre_bt_auto_report = self.dm.cur_bt_auto_report;
        Ok(())
    }

    /// `btc8723b2ant_fw_dac_swing_lvl` → `set_fw_dac_swing_level`.
    async fn fw_dac_swing_lvl<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, lvl: u8) -> R {
        self.dm.cur_fw_dac_swing_lvl = lvl;
        if !force && self.dm.pre_fw_dac_swing_lvl == self.dm.cur_fw_dac_swing_lvl {
            return Ok(());
        }
        cx.fill_h2c(H2C_DAC_SWING, &[lvl]).await?;
        self.dm.pre_fw_dac_swing_lvl = self.dm.cur_fw_dac_swing_lvl;
        Ok(())
    }

    /// `btc8723b2ant_low_penalty_ra` → `btc8723b_set_penalty_txrate`.
    async fn low_penalty_ra<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, low: bool) -> R {
        self.dm.cur_low_penalty_ra = low;
        if !force && self.dm.pre_low_penalty_ra == self.dm.cur_low_penalty_ra {
            return Ok(());
        }
        // Normal rate except MCS7/6/5, OFDM54/48/36 retry penalty.
        let cmd = if low {
            [0x6, 0x1, 0x00, 0xf4, 0xf5, 0xf6]
        } else {
            [0x6, 0, 0, 0, 0, 0]
        };
        cx.fill_h2c(H2C_LOW_PENALTY_RA, &cmd).await?;
        self.dm.pre_low_penalty_ra = self.dm.cur_low_penalty_ra;
        Ok(())
    }

    /// `btc8723b2ant_dac_swing` → `set_sw_fulltime_dac_swing` →
    /// `set_dac_swing_reg` (0x883 bits 5:1; 0x18 when off).
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
        cx.write_1byte_bitmask(0x883, 0x3e, val)?;
        self.dm.pre_dac_swing_on = self.dm.cur_dac_swing_on;
        self.dm.pre_dac_swing_lvl = self.dm.cur_dac_swing_lvl;
        Ok(())
    }

    /// `btc8723b2ant_coex_table` → `set_coex_table`.
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

    /// `btc8723b2ant_coex_table_with_type` (types above 15 write nothing).
    fn coex_table_with_type<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, ty: u8) -> R {
        let Some(&(a, b)) = COEX_TABLES.get(usize::from(ty)) else {
            return Ok(());
        };
        self.coex_table(cx, force, a, b, 0x00ff_ffff, 0x3)
    }

    /// `btc8723b2ant_ignore_wlan_act` → `set_fw_ignore_wlan_act`.
    async fn ignore_wlan_act<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, on: bool) -> R {
        self.dm.cur_ignore_wlan_act = on;
        if !force && self.dm.pre_ignore_wlan_act == self.dm.cur_ignore_wlan_act {
            return Ok(());
        }
        cx.fill_h2c(H2C_IGNORE_WLAN_ACT, &[u8::from(on)]).await?;
        self.dm.pre_ignore_wlan_act = self.dm.cur_ignore_wlan_act;
        Ok(())
    }

    /// `btc8723b2ant_lps_rpwm` → `set_lps_rpwm`.
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

    /// `btc8723b2ant_set_fw_ps_tdma`.
    async fn set_fw_ps_tdma<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, mut b: [u8; 5]) -> R {
        if self.sta.a2dp_exist && self.sta.hid_exist {
            b[4] |= 0x1;
        }
        self.dm.ps_tdma_para = b;
        cx.fill_h2c(H2C_TDMA, &b).await
    }

    /// `btc8723b2ant_sw_mechanism` (only the low-penalty RA is acted on).
    async fn sw_mechanism<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        _shrink_rx_lpf: bool,
        low_penalty_ra: bool,
    ) -> R {
        self.low_penalty_ra(cx, NORMAL_EXEC, low_penalty_ra).await
    }

    /// `sw_mechanism(bw == HT40, low_penalty_ra, false, false)`.
    async fn sw_mechanism_bw<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, low_penalty_ra: bool) -> R {
        let ht40 = cx.btc.wifi.bw() == WifiBw::Ht40;
        self.sw_mechanism(cx, ht40, low_penalty_ra).await
    }

    /// `btc8723b2ant_set_ant_path` (`wifi_off` is unused in Linux).
    pub async fn set_ant_path<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        antpos_type: u8,
        init_hwcfg: bool,
        _wifi_off: bool,
    ) -> R {
        // BTC_GET_BL_EXT_SWITCH is false on rtlwifi.
        let fw_ver = cx.btc.wifi.fw_ver();
        let use_ext_switch = fw_ver < 0xc_0000;
        let main_port = cx.btc.board_info.btdm_ant_pos == BTC_ANTENNA_AT_MAIN_PORT;
        if init_hwcfg {
            cx.write_1byte_bitmask(0x39, 0x8, 0x1)?;
            cx.write_1byte(0x974, 0xff)?;
            cx.write_1byte_bitmask(0x944, 0x3, 0x3)?;
            cx.write_1byte(0x930, 0x77)?;
            cx.write_1byte_bitmask(0x67, 0x20, 0x1)?;
            if fw_ver >= 0x18_0000 {
                // Use H2C to set GNT_BT to HIGH.
                cx.fill_h2c(H2C_BT_CALIBRATION, &[1]).await?;
            } else {
                // Set GRAN_BT = 1.
                cx.write_1byte(0x765, 0x18)?;
            }
            cx.write_4byte(0x948, 0x0)?;
            // WiFi TRx mask off.
            cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
            let h2c = [u8::from(!main_port), u8::from(use_ext_switch)];
            cx.fill_h2c(H2C_ANT_SEL, &h2c).await?;
        } else if fw_ver >= 0x18_0000 {
            // Use H2C to set GNT_BT to "Control by PTA".
            cx.fill_h2c(H2C_BT_CALIBRATION, &[0]).await?;
        } else {
            cx.write_1byte(0x765, 0x0)?;
        }
        if use_ext_switch {
            if init_hwcfg {
                // 0x4c[23] = 0, 0x4c[24] = 1: antenna control by WL/BT.
                let v = cx.read_4byte(0x4c)?;
                cx.write_4byte(0x4c, (v & !(1 << 23)) | (1 << 24))?;
            }
            // Fixed internal switch S1->WiFi, S0->BT.
            if main_port {
                cx.write_2byte(0x948, 0x0)?;
            } else {
                cx.write_2byte(0x948, 0x280)?;
            }
            match antpos_type {
                // Ext switch main at WiFi.
                BTC_ANT_WIFI_AT_MAIN => cx.write_1byte_bitmask(0x92c, 0x3, 0x1)?,
                // Ext switch aux at WiFi.
                BTC_ANT_WIFI_AT_AUX => cx.write_1byte_bitmask(0x92c, 0x3, 0x2)?,
                _ => {}
            }
        } else {
            if init_hwcfg {
                // 0x4c[23] = 1, 0x4c[24] = 0: antenna control by 0x64.
                let v = cx.read_4byte(0x4c)?;
                cx.write_4byte(0x4c, (v | (1 << 23)) & !(1 << 24))?;
            }
            // Fixed external switch S1->Main, S0->Aux.
            cx.write_1byte_bitmask(0x64, 0x1, 0x0)?;
            match antpos_type {
                BTC_ANT_WIFI_AT_MAIN => cx.write_2byte(0x948, 0x0)?,
                BTC_ANT_WIFI_AT_AUX => cx.write_2byte(0x948, 0x280)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// `btc8723b2ant_ps_tdma`.
    pub async fn ps_tdma<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        force: bool,
        turn_on: bool,
        ty: u8,
    ) -> R {
        let tmp = self.wifi_thres();
        let wifi_rssi_state = self.wifi_rssi_state(cx, 0, 2, tmp, 0);
        let tmp = self.bt_thres();
        let bt_rssi_state = self.bt_rssi_state(2, tmp, 0);
        self.dm.cur_ps_tdma_on = turn_on;
        self.dm.cur_ps_tdma = ty;
        let mut ty = ty;
        if !(wifi_rssi_state.high() && bt_rssi_state.high()) && turn_on {
            // For WiFi RSSI low or BT RSSI low.
            ty = ty.wrapping_add(100);
            self.dm.is_switch_to_1dot5_ant = true;
        } else {
            self.dm.is_switch_to_1dot5_ant = false;
        }
        if !force
            && self.dm.pre_ps_tdma_on == self.dm.cur_ps_tdma_on
            && self.dm.pre_ps_tdma == self.dm.cur_ps_tdma
        {
            return Ok(());
        }
        let adj = wifi_duration_adjust(self.sta.scan_ap_num, self.sta.a2dp_bit_pool);
        let l = cx.btc.bt_link_info;
        let b4 = u8::from(l.slave_role && l.a2dp_exist);
        self.set_fw_ps_tdma(cx, ps_tdma_bytes(turn_on, ty, adj, b4))
            .await?;
        self.dm.pre_ps_tdma_on = self.dm.cur_ps_tdma_on;
        self.dm.pre_ps_tdma = self.dm.cur_ps_tdma;
        Ok(())
    }

    /// `btc8723b2ant_ps_tdma_check_for_power_save_state`.
    async fn ps_tdma_chk_pwr_save<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, new_ps_state: bool) -> R {
        let lps_mode = cx.lps_mode();
        // Already under LPS and leaving it, or not under LPS and entering
        // it: TDMA off first.
        if (lps_mode != 0) != new_ps_state {
            self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        }
        Ok(())
    }

    /// `btc8723b2ant_power_save_state`.
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

    /// `btc8723b2ant_coex_alloff`.
    async fn coex_alloff<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        // Fw all off.
        self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
        // Sw all off.
        self.sw_mechanism(cx, false, false).await?;
        // Hw all off.
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)
    }

    /// `btc8723b2ant_init_coex_dm`.
    async fn init_coex_dm_inner<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        // Force to reset coex mechanism.
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
        self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
            .await?;
        self.ps_tdma(cx, FORCE_EXEC, false, 1).await?;
        self.fw_dac_swing_lvl(cx, FORCE_EXEC, 6).await?;
        self.dec_bt_pwr(cx, FORCE_EXEC, 0).await?;
        self.sw_mechanism(cx, false, false).await?;
        self.sta.pop_event_cnt = 0;
        Ok(())
    }

    /// `btc8723b2ant_action_bt_inquiry`.
    async fn action_bt_inquiry<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        cx.disable_low_power(true);
        let w = cx.btc.wifi;
        let (connected, scan, link) = (w.connected(), w.scanning, w.linking);
        self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
            .await?;
        if self.sta.bt_abnormal_scan {
            self.ps_tdma(cx, NORMAL_EXEC, true, 23).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 3)?;
        } else if scan || link || connected {
            // BTC_GET_BL_WIFI_ROAM is the LINKING state too.
            self.coex_table_with_type(cx, NORMAL_EXEC, 15)?;
            self.ps_tdma(cx, NORMAL_EXEC, true, 22).await?;
        } else {
            self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
            self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        }
        self.fw_dac_swing_lvl(cx, FORCE_EXEC, 6).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
        self.sw_mechanism(cx, false, false).await
    }

    /// `btc8723b2ant_action_wifi_link_process`.
    async fn action_wifi_link_process<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.coex_table_with_type(cx, NORMAL_EXEC, 15)?;
        self.ps_tdma(cx, NORMAL_EXEC, true, 22).await?;
        self.sw_mechanism(cx, false, false).await?;
        // Linux logs 0x948 / 0x765 / 0x76e.
        cx.read_4byte(0x948)?;
        cx.read_1byte(0x765)?;
        cx.read_1byte(0x76e)?;
        Ok(())
    }

    /// `btc8723b2ant_action_wifi_idle_process`.
    async fn action_wifi_idle_process<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
    ) -> Result<bool, Error> {
        let off = self.dm.switch_thres_offset;
        let tmp = WIFI_RSSI_COEXSWITCH_THRES
            .wrapping_sub(off)
            .wrapping_sub(off);
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let wifi_rssi_state1 = self.wifi_rssi_state(cx, 1, 2, tmp, 0);
        let tmp = BT_RSSI_COEXSWITCH_THRES.wrapping_sub(off).wrapping_sub(off);
        self.bt_rssi_state(2, tmp, 0);
        // BTC_GET_U1_AP_NUM is read but unused.
        if wifi_rssi_state1.high() && self.sta.hid_exist && self.sta.a2dp_exist {
            self.dac_swing(cx, NORMAL_EXEC, true, 0x6).await?;
            self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
            self.sw_mechanism(cx, false, false).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
            self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
                .await?;
            self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
            return Ok(true);
        }
        self.dac_swing(cx, NORMAL_EXEC, true, 0x18).await?;
        Ok(false)
    }

    /// The "all off" body `is_common_action` runs for an idle link.
    async fn common_idle<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        dac_lvl: u8,
        shrink_rx_lpf: bool,
    ) -> R {
        self.limited_rx(cx, NORMAL_EXEC, false, false, 0x8);
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, dac_lvl).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
        self.sw_mechanism(cx, shrink_rx_lpf, false).await
    }

    /// `btc8723b2ant_is_common_action`.
    async fn is_common_action<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<bool, Error> {
        let bt_hs_on = cx.hs_operation();
        let w = cx.btc.wifi;
        if !w.connected() {
            cx.disable_low_power(false);
            self.common_idle(cx, 6, false).await?;
            return Ok(true);
        }
        match self.dm.bt_status {
            BtStatus::NonConnectedIdle => {
                cx.disable_low_power(false);
                self.common_idle(cx, 0xb, false).await?;
                Ok(true)
            }
            BtStatus::ConnectedIdle => {
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

    /// `btc8723b2ant_tdma_duration_adjust`.
    async fn tdma_duration_adjust<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        sco_hid: bool,
        tx_pause: bool,
        max_interval: u8,
    ) -> R {
        if !self.dm.auto_tdma_adjust {
            self.dm.auto_tdma_adjust = true;
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
            let mut retry_count = self.sta.bt_retry_cnt;
            if self.sta.low_priority_tx > 1050 || self.sta.low_priority_rx > 1250 {
                retry_count = retry_count.wrapping_add(1);
            }
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

    /// `btc8723b2ant_action_sco` (SCO only or SCO + PAN(HS)).
    async fn action_sco<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let t = self.bt_thres();
        let bt = self.bt_rssi_state(2, t, 0);
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 0x8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 4).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        let ty = if cx.btc.wifi.bw() == WifiBw::Legacy {
            // For SCO quality at 11b/g mode.
            2
        } else {
            // For SCO quality & WiFi performance balance at 11n mode.
            8
        };
        self.coex_table_with_type(cx, NORMAL_EXEC, ty)?;
        // For voice quality.
        self.ps_tdma(cx, NORMAL_EXEC, false, 0).await?;
        self.sw_mechanism_bw(cx, true).await
    }

    /// `btc8723b2ant_action_hid`.
    async fn action_hid<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let t = self.bt_thres();
        let bt = self.bt_rssi_state(2, t, 0);
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 0x8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        let ty = if cx.btc.wifi.bw() == WifiBw::Legacy {
            7
        } else {
            9
        };
        self.coex_table_with_type(cx, NORMAL_EXEC, ty)?;
        self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
            .await?;
        let ty = if bt.high() { 9 } else { 13 };
        self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
        self.sw_mechanism_bw(cx, true).await
    }

    /// `btc8723b2ant_action_a2dp` (A2DP only / PAN(EDR) only /
    /// A2DP + PAN(HS)).
    async fn action_a2dp<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let w1 = self.wifi_rssi_state(cx, 1, 2, 40, 0);
        let t = self.bt_thres();
        let bt = self.bt_rssi_state(2, t, 0);
        let ap_num = cx.btc.wifi.ap_num;
        // Define the office environment.
        if ap_num >= 10 && w1.high() {
            cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
            self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
            self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
            self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
            return self.sw_mechanism_bw(cx, false).await;
        }
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 0x8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        self.table_and_ps(cx, w1.high() && bt.high(), 7, 13).await?;
        self.tdma_duration_adjust(cx, false, !bt.high(), 1).await?;
        self.sw_mechanism_bw(cx, false).await
    }

    /// `btc8723b2ant_action_a2dp_pan_hs`.
    async fn action_a2dp_pan_hs<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (w1, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 0x8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        self.table_and_ps(cx, w1.high() && bt.high(), 7, 13).await?;
        self.tdma_duration_adjust(cx, false, true, 2).await?;
        self.sw_mechanism_bw(cx, false).await
    }

    /// `btc8723b2ant_action_pan_edr`.
    async fn action_pan_edr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (w1, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 0x8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        self.table_and_ps(cx, w1.high() && bt.high(), 10, 13)
            .await?;
        let ty = if bt.high() { 1 } else { 5 };
        self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
        self.sw_mechanism_bw(cx, false).await
    }

    /// `btc8723b2ant_action_pan_hs` (PAN(HS) only).
    async fn action_pan_hs<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (_, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 0x8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 7)?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 1).await?;
        self.sw_mechanism_bw(cx, false).await
    }

    /// `btc8723b2ant_action_pan_edr_a2dp` (PAN(EDR) + A2DP).
    async fn action_pan_edr_a2dp<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (w1, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        if w1.high() && bt.high() {
            self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
                .await?;
        } else {
            self.power_save_state(cx, PowerSave::LpsOn, 0x50, 0x4)
                .await?;
        }
        let ht40 = cx.btc.wifi.bw() == WifiBw::Ht40;
        if bt.high() {
            self.coex_table_with_type(cx, NORMAL_EXEC, 12)?;
            self.tdma_duration_adjust(cx, false, ht40, 3).await?;
        } else {
            self.coex_table_with_type(cx, NORMAL_EXEC, 7)?;
            self.ps_tdma(cx, NORMAL_EXEC, true, 3).await?;
        }
        self.sw_mechanism(cx, ht40, false).await
    }

    /// `btc8723b2ant_action_pan_edr_hid`.
    async fn action_pan_edr_hid<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (w1, bt) = self.rssi_prologue(cx);
        let ht40 = cx.btc.wifi.bw() == WifiBw::Ht40;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 0x8);
        self.dec_bt_pwr_by(cx, bt).await?;
        self.table_and_ps(cx, w1.high() && bt.high(), 7, 14).await?;
        if bt.high() {
            if ht40 {
                self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 3).await?;
                cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x780).await?;
            } else {
                self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
                cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
            }
            self.tdma_duration_adjust(cx, true, false, 2).await?;
        } else {
            self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
            cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
            self.tdma_duration_adjust(cx, true, true, 2).await?;
        }
        self.sw_mechanism(cx, ht40, true).await
    }

    /// `btc8723b2ant_action_hid_a2dp_pan_edr` (HID + A2DP + PAN(EDR)).
    async fn action_hid_a2dp_pan_edr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let (w1, bt) = self.rssi_prologue(cx);
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, false, 0x8);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr_by(cx, bt).await?;
        self.table_and_ps(cx, w1.high() && bt.high(), 7, 14).await?;
        let ht40 = cx.btc.wifi.bw() == WifiBw::Ht40;
        if bt.high() {
            if ht40 {
                self.tdma_duration_adjust(cx, true, true, 2).await?;
            } else {
                self.tdma_duration_adjust(cx, true, false, 3).await?;
            }
        } else {
            self.tdma_duration_adjust(cx, true, true, 3).await?;
        }
        self.sw_mechanism(cx, ht40, true).await
    }

    /// `btc8723b2ant_action_hid_a2dp`.
    async fn action_hid_a2dp<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        // Linux declares `ap_num = 0` here and never reads
        // BTC_GET_U1_AP_NUM, so every `ap_num < 10` test holds.
        let ap_num = 0u8;
        self.wifi_rssi_state(cx, 0, 2, 15, 0);
        let t = self.wifi_thres();
        let w1 = self.wifi_rssi_state(cx, 1, 2, t, 0);
        let t = self.bt_thres();
        let bt = self.bt_rssi_state(3, t, 37);
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x0).await?;
        self.limited_rx(cx, NORMAL_EXEC, false, true, 0x5);
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        let bw = cx.btc.wifi.bw();
        let lvl = if bw == WifiBw::Legacy {
            if bt.high() || bt.medium() {
                2
            } else {
                0
            }
        } else if bt.high() {
            if ap_num < 10 {
                4
            } else {
                2
            }
        } else if bt.medium() {
            2
        } else {
            0
        };
        self.dec_bt_pwr(cx, NORMAL_EXEC, lvl).await?;
        self.table_and_ps(cx, w1.high() && bt.high(), 7, 14).await?;
        let max_interval = if ap_num < 10 { 1 } else { 3 };
        if bt.high() {
            self.tdma_duration_adjust(cx, true, false, max_interval)
                .await?;
        } else {
            self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 18).await?;
            cx.write_1byte(0x456, 0x38)?;
            cx.write_2byte(0x42a, 0x0808)?;
            cx.write_4byte(0x430, 0x0)?;
            cx.write_4byte(0x434, 0x0101_0000)?;
            self.tdma_duration_adjust(cx, true, true, max_interval)
                .await?;
        }
        self.sw_mechanism_bw(cx, true).await
    }

    /// `btc8723b2ant_action_wifi_multi_port`.
    async fn action_wifi_multi_port<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.fw_dac_swing_lvl(cx, NORMAL_EXEC, 6).await?;
        self.dec_bt_pwr(cx, NORMAL_EXEC, 0).await?;
        self.sw_mechanism(cx, false, false).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)?;
        self.power_save_state(cx, PowerSave::WifiNative, 0x0, 0x0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 1).await
    }

    /// `btc8723b2ant_run_coexist_mechanism`.
    async fn run_coexist_mechanism<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if cx.btc.manual_control || self.sta.under_ips {
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
            self.dm.auto_tdma_adjust = false;
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

    /// `btc8723b2ant_wifioff_hwcfg`.
    async fn wifioff_hwcfg<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        // Set wlan_act to low.
        cx.write_1byte(0x76e, 0x4)?;
        // WiFi goto standby while GNT_BT 0-->1.
        cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x780).await?;
        if cx.btc.wifi.fw_ver() >= 0x18_0000 {
            // Use H2C to set GNT_BT to HIGH.
            cx.fill_h2c(H2C_BT_CALIBRATION, &[1]).await?;
        } else {
            cx.write_1byte(0x765, 0x18)?;
        }
        // BTC_GET_BL_WIFI_IS_IN_MP_MODE is false on rtlwifi.
        cx.write_1byte_bitmask(0x67, 0x20, 0x0)
    }

    /// `ex_btc8723b2ant_init_hwconfig`.
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
        cx.btc.auto_report_2ant = true;
        Ok(())
    }

    /// `ex_btc8723b2ant_media_status_notify`.
    async fn media_status<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Media) -> R {
        let mut h2c = [0u8; 3];
        let chnl = cx.btc.wifi.central_chnl();
        // Only 2.4G needs to inform the channel mask to firmware.
        if ty == Media::Connect && chnl <= 14 {
            h2c[0] = 0x1;
            h2c[1] = chnl;
            h2c[2] = if cx.btc.wifi.bw() == WifiBw::Ht40 || cx.btc.wifi.ap_num < 10 {
                0x30
            } else {
                0x20
            };
        }
        self.dm.wifi_chnl_info = h2c;
        cx.fill_h2c(H2C_WIFI_CHNL, &h2c).await
    }
}

impl Algorithm for B8723b2Ant {
    /// `ex_btc8723b2ant_power_on_setting`.
    async fn power_on_setting<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        cx.write_1byte(0x67, 0x20)?;
        // Enable BB, REG_SYS_FUNC_EN such that we can write 0x948
        // correctly.
        let v = cx.read_2byte(0x2)?;
        cx.write_2byte(0x2, v | 0x3)?;
        cx.write_4byte(0x948, 0x0)?;
        if cx.btc.chip_interface == ChipInterface::Usb {
            // Fixed at S0 for USB.
            cx.btc.board_info.btdm_ant_pos = BTC_ANTENNA_AT_AUX_PORT;
        } else {
            match cx.btc.board_info.single_ant_path {
                0 => cx.btc.board_info.btdm_ant_pos = BTC_ANTENNA_AT_MAIN_PORT,
                1 => cx.btc.board_info.btdm_ant_pos = BTC_ANTENNA_AT_AUX_PORT,
                _ => {}
            }
            // BTC_SET_ACT_ANTPOSREGRISTRY_CTRL has no rtlwifi handler.
        }
        Ok(())
    }

    /// `ex_btc8723b2ant_pre_load_firmware`.
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

    /// `ex_btc8723b2ant_init_hwconfig` (the 2-antenna handler takes no
    /// `wifi_only`).
    async fn init_hw_config<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, _wifi_only: bool) -> R {
        self.init_hwconfig_inner(cx).await
    }

    /// `ex_btc8723b2ant_init_coex_dm`.
    async fn init_coex_dm<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.init_coex_dm_inner(cx).await
    }

    /// `ex_btc8723b2ant_ips_notify`.
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

    /// `ex_btc8723b2ant_lps_notify`.
    async fn lps_notify<H: Hal>(&mut self, _cx: &mut Ctx<'_, H>, ty: Lps) -> R {
        self.sta.under_lps = ty == Lps::Enable;
        Ok(())
    }

    /// `ex_btc8723b2ant_scan_notify` (the register reads are logged in
    /// Linux).
    async fn scan_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, _ty: Scan) -> R {
        cx.read_4byte(0x948)?;
        cx.read_1byte(0x765)?;
        cx.read_1byte(0x76e)?;
        self.sta.scan_ap_num = cx.btc.wifi.ap_num;
        Ok(())
    }

    /// `ex_btc8723b2ant_connect_notify` (log only).
    async fn connect_notify<H: Hal>(&mut self, _cx: &mut Ctx<'_, H>, _ty: Associate) -> R {
        Ok(())
    }

    /// `ex_btc8723b2ant_media_status_notify`.
    async fn media_status_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Media) -> R {
        self.media_status(cx, ty).await
    }

    /// `ex_btc8723b2ant_special_packet_notify` (log only).
    async fn special_packet_notify<H: Hal>(&mut self, _cx: &mut Ctx<'_, H>, _ty: Packet) -> R {
        Ok(())
    }

    /// `ex_btc8723b2ant_bt_info_notify`.
    async fn bt_info_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, buf: &[u8]) -> R {
        self.sta.c2h_bt_info_req_sent = false;
        let n = buf.len().min(10);
        let mut rsp_source = usize::from(buf.first().copied().unwrap_or(0) & 0xf);
        if rsp_source >= BT_INFO_SRC_MAX {
            rsp_source = BT_INFO_SRC_WIFI_FW;
        }
        let s = &mut self.sta;
        s.bt_info_c2h_cnt[rsp_source] = s.bt_info_c2h_cnt[rsp_source].wrapping_add(1);
        s.bt_info_c2h[rsp_source][..n].copy_from_slice(&buf[..n]);
        let mut bt_info = if n > 1 { buf[1] } else { 0 };
        if cx.btc.manual_control {
            return Ok(());
        }
        if rsp_source != BT_INFO_SRC_WIFI_FW {
            let row = self.sta.bt_info_c2h[rsp_source];
            let s = &mut self.sta;
            s.bt_retry_cnt = row[2] & 0xf;
            if s.bt_retry_cnt >= 1 {
                s.pop_event_cnt = s.pop_event_cnt.wrapping_add(1);
            }
            s.bt_rssi = row[3].wrapping_mul(2).wrapping_add(10);
            s.bt_info_ext = row[4];
            s.c2h_bt_remote_name_req = row[2] & 0x20 != 0;
            s.a2dp_bit_pool = if row[1] == 0x49 { row[6] } else { 0 };
            // BT reset: re-inform the Wi-Fi channel.
            if s.bt_info_ext & (1 << 1) != 0 {
                let ty = if cx.btc.wifi.connected() {
                    Media::Connect
                } else {
                    Media::Disconnect
                };
                self.media_status(cx, ty).await?;
            }
            if self.sta.bt_info_ext & (1 << 3) != 0 {
                self.ignore_wlan_act(cx, FORCE_EXEC, false).await?;
            }
            if !cx.btc.auto_report_2ant && self.sta.bt_info_ext & (1 << 4) == 0 {
                self.bt_auto_report(cx, FORCE_EXEC, true).await?;
            }
        }
        let s = &mut self.sta;
        s.c2h_bt_inquiry_page = bt_info & BT_INFO_B_INQ_PAGE != 0;
        if bt_info & BT_INFO_B_CONNECTION == 0 {
            s.bt_link_exist = false;
            s.pan_exist = false;
            s.a2dp_exist = false;
            s.hid_exist = false;
            s.sco_exist = false;
        } else {
            s.bt_link_exist = true;
            s.pan_exist = bt_info & BT_INFO_B_FTP != 0;
            s.a2dp_exist = bt_info & BT_INFO_B_A2DP != 0;
            s.hid_exist = bt_info & BT_INFO_B_HID != 0;
            s.sco_exist = bt_info & BT_INFO_B_SCO_ESCO != 0;
            // Work around for HID with a missing profile notification.
            if !s.hid_exist
                && !s.c2h_bt_inquiry_page
                && !s.sco_exist
                && s.high_priority_tx.wrapping_add(s.high_priority_rx) >= 160
            {
                s.hid_exist = true;
                bt_info |= 0x28;
            }
        }
        self.update_bt_link_info(cx);
        self.dm.bt_status = if bt_info & BT_INFO_B_CONNECTION == 0 {
            BtStatus::NonConnectedIdle
        } else if bt_info == BT_INFO_B_CONNECTION {
            // Connection exists but no busy.
            BtStatus::ConnectedIdle
        } else if bt_info & (BT_INFO_B_SCO_ESCO | BT_INFO_B_SCO_BUSY) != 0 {
            BtStatus::ScoBusy
        } else if bt_info & BT_INFO_B_ACL_BUSY != 0 {
            BtStatus::AclBusy
        } else {
            BtStatus::Max
        };
        let busy = matches!(
            self.dm.bt_status,
            BtStatus::AclBusy | BtStatus::ScoBusy | BtStatus::AclScoBusy
        );
        // BTC_SET_BL_BT_TRAFFIC_BUSY / BTC_SET_BL_BT_LIMITED_DIG.
        cx.btc.bt_info.bt_busy = busy;
        self.dm.limited_dig = busy;
        cx.btc.bt_info.limited_dig = busy;
        self.run_coexist_mechanism(cx).await
    }

    /// `ex_btc8723b2ant_halt_notify`.
    async fn halt_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.wifioff_hwcfg(cx).await?;
        self.ignore_wlan_act(cx, FORCE_EXEC, true).await?;
        self.media_status(cx, Media::Disconnect).await
    }

    /// `ex_btc8723b2ant_pnp_notify`.
    async fn pnp_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, state: Pnp) -> R {
        match state {
            Pnp::Sleep => {
                self.sta.under_ips = false;
                self.sta.under_lps = false;
                Ok(())
            }
            Pnp::WakeUp => {
                self.init_hwconfig_inner(cx).await?;
                self.init_coex_dm_inner(cx).await?;
                self.query_bt_info(cx).await
            }
            Pnp::SleepKeepAnt => Ok(()),
        }
    }

    /// `ex_btc8723b2ant_periodical`.
    async fn periodical<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if self.sta.dis_ver_info_cnt <= 5 {
            self.sta.dis_ver_info_cnt += 1;
            if self.sta.dis_ver_info_cnt == 3 {
                // Antenna config to set 0x765 = 0x0 (GNT_BT control by
                // PTA) after initial.
                self.set_ant_path(cx, BTC_ANT_WIFI_AT_MAIN, false, false)
                    .await?;
            }
        }
        if !cx.btc.auto_report_2ant {
            return self.query_bt_info(cx).await;
        }
        self.monitor_bt_ctr(cx)?;
        self.monitor_wifi_ctr(cx)?;
        // Workaround for the wrong HID notification.
        if self
            .sta
            .high_priority_tx
            .wrapping_add(self.sta.high_priority_rx)
            < 50
            && cx.btc.bt_link_info.hid_exist
        {
            cx.btc.bt_link_info.hid_exist = false;
        }
        if self.is_wifi_status_changed(cx) || self.dm.auto_tdma_adjust {
            self.run_coexist_mechanism(cx).await?;
        }
        Ok(())
    }
}

/// `exhalbtc_*`'s RTL8723B dispatch: the 2-antenna algorithm when
/// `btdm_ant_num == 2`, the 1-antenna one when it is 1, nothing otherwise
/// (both keep their state, as Linux's file-scope `coex_dm`/`coex_sta`
/// do, since `btdm_ant_num` is read on every notify).
#[derive(Clone, Debug, Default)]
pub struct Rtl8723b {
    pub one: super::b8723b1ant::B8723b1Ant,
    pub two: B8723b2Ant,
}

macro_rules! dispatch {
    ($self:ident, $cx:ident, $method:ident $(, $arg:expr)*) => {
        match $cx.btc.board_info.btdm_ant_num {
            2 => $self.two.$method($cx $(, $arg)*).await,
            1 => $self.one.$method($cx $(, $arg)*).await,
            _ => Ok(()),
        }
    };
}

impl Algorithm for Rtl8723b {
    async fn power_on_setting<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        dispatch!(self, cx, power_on_setting)
    }
    async fn pre_load_firmware<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        dispatch!(self, cx, pre_load_firmware)
    }
    async fn init_hw_config<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, wifi_only: bool) -> R {
        dispatch!(self, cx, init_hw_config, wifi_only)
    }
    async fn init_coex_dm<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        dispatch!(self, cx, init_coex_dm)
    }
    async fn ips_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Ips) -> R {
        dispatch!(self, cx, ips_notify, ty)
    }
    async fn lps_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Lps) -> R {
        dispatch!(self, cx, lps_notify, ty)
    }
    async fn scan_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Scan) -> R {
        dispatch!(self, cx, scan_notify, ty)
    }
    async fn connect_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Associate) -> R {
        dispatch!(self, cx, connect_notify, ty)
    }
    async fn media_status_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Media) -> R {
        dispatch!(self, cx, media_status_notify, ty)
    }
    async fn special_packet_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Packet) -> R {
        dispatch!(self, cx, special_packet_notify, ty)
    }
    async fn bt_info_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, buf: &[u8]) -> R {
        dispatch!(self, cx, bt_info_notify, buf)
    }
    async fn halt_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        dispatch!(self, cx, halt_notify)
    }
    async fn pnp_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, state: Pnp) -> R {
        dispatch!(self, cx, pnp_notify, state)
    }
    async fn periodical<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        dispatch!(self, cx, periodical)
    }
}
