// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723B single-antenna BT coexistence: `btcoexist/halbtc8723b1ant.{c,h}`
//! (Linux 7.3-rc4, `glcoex_ver_8723b_1ant = 0x47`, 20130918).
//!
//! The Linux file-scope `coex_dm` / `coex_sta` and the function-local
//! `static`s (`num_of_bt_counter_chk`, `cck_lock_counter`, the
//! `is_wifi_status_changed` / `ps_tdma` previous-busy flags, the
//! `tdma_dur_adj_for_acl` `up/dn/m/n/wait_count` and `bt_disable_cnt`)
//! are per-instance fields of [`B8723b1Ant`]. Every handler is the Linux
//! one in order, including register reads Linux only logs (they are real
//! bus reads). `ex_btc8723b1ant_display_coex_info` (debugfs) is not
//! carried.
//!
//! What the glue makes constant on rtlwifi (and therefore here):
//! `BTC_GET_BL_HS_OPERATION` false, `BTC_GET_BL_EXT_SWITCH` false,
//! `BTC_GET_BL_WIFI_IS_IN_MP_MODE` false, `BTC_GET_U1_IOT_PEER`
//! `BTC_IOT_PEER_UNKNOWN`; `auto_report_1ant` is never set, so the
//! periodical only queries BT info and runs the BT enable/disable monitor.

#![allow(dead_code)]

use super::btc::{
    Associate, BtReg, Ctx, Hal, Ips, Lps, Media, Packet, Pnp, PowerSave, Scan, WifiBw,
    BTC_ANTENNA_AT_AUX_PORT, BTC_ANTENNA_AT_MAIN_PORT, BTC_ANT_PATH_BT, BTC_ANT_PATH_PTA,
    BTC_ANT_PATH_WIFI, BTC_RF_A, FORCE_EXEC, NORMAL_EXEC, WIFI_P2P_GO_CONNECTED,
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

/// `BTC_RSSI_COEX_THRESH_TOL_8723B_1ANT`.
pub const RSSI_COEX_THRESH_TOL: u8 = 2;
/// `BT_8723B_1ANT_WIFI_NOISY_THRESH`.
pub const WIFI_NOISY_THRESH: u8 = 50;

/// `enum _BT_INFO_SRC_8723B_1ANT`.
pub const BT_INFO_SRC_WIFI_FW: usize = 0;
pub const BT_INFO_SRC_BT_RSP: usize = 1;
pub const BT_INFO_SRC_BT_ACTIVE_SEND: usize = 2;
pub const BT_INFO_SRC_MAX: usize = 3;

/// `BTC_IOT_PEER_BROADCOM` / `BTC_IOT_PEER_CISCO`.
const IOT_PEER_BROADCOM: u8 = 3;
const IOT_PEER_CISCO: u8 = 6;

/// H2C element ids this algorithm sends.
pub const H2C_TDMA: u8 = 0x60;
pub const H2C_BT_INFO: u8 = 0x61;
pub const H2C_IGNORE_WLAN_ACT: u8 = 0x63;
pub const H2C_ANT_SEL: u8 = 0x65;
pub const H2C_WIFI_CHNL: u8 = 0x66;
pub const H2C_BT_AUTO_REPORT: u8 = 0x68;
pub const H2C_LOW_PENALTY_RA: u8 = 0x69;
pub const H2C_BT_CALIBRATION: u8 = 0x6e;

/// `enum _BT_8723B_1ANT_BT_STATUS`.
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

impl BtStatus {
    const fn busy(self) -> bool {
        matches!(self, Self::AclBusy | Self::ScoBusy | Self::AclScoBusy)
    }
    const fn sco_busy(self) -> bool {
        matches!(self, Self::ScoBusy | Self::AclScoBusy)
    }
}

/// `enum _BT_8723B_1ANT_WIFI_STATUS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiStatus {
    NonConnectedIdle = 0,
    NonConnectedAssoAuthScan = 1,
    ConnectedScan = 2,
    ConnectedSpecialPkt = 3,
    ConnectedIdle = 4,
    ConnectedBusy = 5,
}

/// `struct coex_dm_8723b_1ant`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoexDm {
    pub pre_ant_pos_type: u8,
    pub cur_ant_pos_type: u8,
    pub cur_ignore_wlan_act: bool,
    pub pre_ignore_wlan_act: bool,
    pub pre_ps_tdma: u8,
    pub cur_ps_tdma: u8,
    pub ps_tdma_para: [u8; 5],
    pub ps_tdma_du_adj_type: u8,
    pub auto_tdma_adjust: bool,
    pub pre_ps_tdma_on: bool,
    pub cur_ps_tdma_on: bool,
    pub pre_bt_auto_report: bool,
    pub cur_bt_auto_report: bool,
    pub pre_lps: u8,
    pub cur_lps: u8,
    pub pre_rpwm: u8,
    pub cur_rpwm: u8,
    pub pre_low_penalty_ra: bool,
    pub cur_low_penalty_ra: bool,
    pub pre_val0x6c0: u32,
    pub cur_val0x6c0: u32,
    pub pre_val0x6c4: u32,
    pub cur_val0x6c4: u32,
    pub pre_val0x6c8: u32,
    pub cur_val0x6c8: u32,
    pub pre_val0x6cc: u8,
    pub cur_val0x6cc: u8,
    pub limited_dig: bool,
    pub backup_arfr_cnt1: u32,
    pub backup_arfr_cnt2: u32,
    pub backup_retry_limit: u16,
    pub backup_ampdu_max_time: u8,
    pub pre_algorithm: u8,
    pub cur_algorithm: u8,
    pub bt_status: BtStatus,
    pub wifi_chnl_info: [u8; 3],
    pub prera_mask: u32,
    pub curra_mask: u32,
    pub pre_arfr_type: u8,
    pub cur_arfr_type: u8,
    pub pre_retry_limit_type: u8,
    pub cur_retry_limit_type: u8,
    pub pre_ampdu_time_type: u8,
    pub cur_ampdu_time_type: u8,
    pub arp_cnt: u32,
    pub error_condition: u8,
}

/// `struct coex_sta_8723b_1ant`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoexSta {
    pub bt_disabled: bool,
    pub bt_link_exist: bool,
    pub sco_exist: bool,
    pub a2dp_exist: bool,
    pub hid_exist: bool,
    pub pan_exist: bool,
    pub bt_hi_pri_link_exist: bool,
    pub num_of_profile: u8,
    pub bt_abnormal_scan: bool,
    pub under_lps: bool,
    pub under_ips: bool,
    pub special_pkt_period_cnt: u32,
    pub high_priority_tx: u32,
    pub high_priority_rx: u32,
    pub low_priority_tx: u32,
    pub low_priority_rx: u32,
    pub bt_rssi: u8,
    pub pre_bt_rssi_state: u8,
    pub pre_wifi_rssi_state: [u8; 4],
    pub bt_tx_rx_mask: bool,
    pub c2h_bt_info_req_sent: bool,
    pub bt_info_c2h: [[u8; 10]; BT_INFO_SRC_MAX],
    pub bt_info_c2h_cnt: [u32; BT_INFO_SRC_MAX],
    pub bt_whck_test: bool,
    pub c2h_bt_inquiry_page: bool,
    pub c2h_bt_remote_name_req: bool,
    pub wifi_is_high_pri_task: bool,
    pub bt_retry_cnt: u8,
    pub bt_info_ext: u8,
    pub scan_ap_num: u8,
    pub cck_ever_lock: bool,
    pub coex_table_type: u8,
    pub force_lps_on: bool,
    pub pop_event_cnt: u32,
    pub crc_ok_cck: u32,
    pub crc_ok_11g: u32,
    pub crc_ok_11n: u32,
    pub crc_ok_11n_agg: u32,
    pub crc_err_cck: u32,
    pub crc_err_11g: u32,
    pub crc_err_11n: u32,
    pub crc_err_11n_agg: u32,
    pub cck_lock: bool,
    pub pre_ccklock: bool,
    pub wrong_profile_notification: u32,
    pub a2dp_bit_pool: u8,
    pub cut_version: u8,
}

/// The Linux function-local statics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statics {
    /// `halbtc8723b1ant_monitor_bt_ctr`.
    pub num_of_bt_counter_chk: u32,
    /// `halbtc8723b1ant_monitor_wifi_ctr`.
    pub cck_lock_counter: u8,
    /// `btc8723b1ant_is_wifi_status_changed`.
    pub pre_wifi_busy: bool,
    pub pre_under_4way: bool,
    pub pre_bt_hs_on: bool,
    /// `halbtc8723b1ant_ps_tdma`.
    pub tdma_pre_wifi_busy: bool,
    /// `btc8723b1ant_tdma_dur_adj_for_acl`.
    pub up: i32,
    pub dn: i32,
    pub m: i32,
    pub n: i32,
    pub wait_count: i32,
    /// `halbtc8723b1ant_monitor_bt_enable_disable`.
    pub bt_disable_cnt: u32,
}

/// `halbtc8723b1ant_coex_table_with_type` rows (0x6c0, 0x6c4); 0x6c8 is
/// always `0xffffff` and 0x6cc `0x3`. Type 4's `cck_ever_lock` variant is
/// [`COEX_TABLE_4_CCK_LOCK`].
pub const COEX_TABLES: [(u32, u32); 16] = [
    (0x5555_5555, 0x5555_5555),
    (0x5555_5555, 0x5a5a_5a5a),
    (0x5a5a_5a5a, 0x5a5a_5a5a),
    (0x5555_5555, 0x5a5a_5a5a),
    (0x5555_5555, 0x5a5a_5a5a),
    (0x5a5a_5a5a, 0x5aaa_5a5a),
    (0x5555_5555, 0xaaaa_aaaa),
    (0xaaaa_aaaa, 0xaaaa_aaaa),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x55dd_55dd, 0x5ada_5ada),
    (0x5fff_5fff, 0xaaaa_aaaa),
    (0x5fff_5fff, 0x5ada_5ada),
    (0x55dd_55dd, 0xaaaa_aaaa),
];
pub const COEX_TABLE_4_CCK_LOCK: (u32, u32) = (0x5555_5555, 0xaaaa_5a5a);

/// `halbtc8723b1ant_ps_tdma`'s `wifi_duration_adjust` (the later `>= 45`
/// tests after `>= 35` are unreachable in Linux too).
pub const fn wifi_duration_adjust(scan_ap_num: u8, a2dp_bit_pool: u8) -> i8 {
    if scan_ap_num <= 5 {
        if a2dp_bit_pool >= 35 {
            -10
        } else {
            5
        }
    } else if scan_ap_num >= 40 {
        if a2dp_bit_pool < 35 {
            -5
        } else if a2dp_bit_pool < 45 {
            -10
        } else {
            -15
        }
    } else if scan_ap_num >= 20 {
        if a2dp_bit_pool >= 45 {
            -15
        } else {
            -10
        }
    } else if a2dp_bit_pool >= 35 {
        -10
    } else {
        0
    }
}

/// The five `halbtc8723b1ant_set_fw_ps_tdma` bytes `halbtc8723b1ant_ps_tdma`
/// selects (before the AP-mode rewrite). `adj` is
/// [`wifi_duration_adjust`]; `slave_a2dp` is `slave_role && a2dp_exist`.
pub fn ps_tdma_bytes(
    turn_on: bool,
    ty: u8,
    force_lps_on: bool,
    adj: i8,
    slave_a2dp: bool,
    scan_ap_num: u8,
) -> [u8; 5] {
    let (mut b0, mut b3, mut b4) = match ty {
        1 | 2 | 9 | 11 | 101 | 102 | 109 | 111 => {
            if !force_lps_on {
                (0x61u8, 0x11u8, 0x10u8)
            } else {
                (0x51, 0x10, 0x50)
            }
        }
        3 | 13 | 14 | 103 | 113 | 114 => (0x51, 0x10, 0x10),
        _ => (0x61, 0x11, 0x11),
    };
    if slave_a2dp {
        b4 |= 0x1;
    }
    if ty > 100 {
        b0 |= 0x82;
        b3 |= 0x60;
    }
    let d = |base: u8| base.wrapping_add(adj as u8);
    if !turn_on {
        return match ty {
            8 => [0x8, 0, 0, 0, 0],
            1 => [0, 0, 0, 0x48, 0],
            _ => [0; 5],
        };
    }
    match ty {
        1 | 101 => [b0, d(0x3a), 0x03, b3, b4],
        2 | 102 => [b0, d(0x2d), 0x03, b3, b4],
        3 => [b0, 0x30, 0x03, b3, b4],
        4 => [0x93, 0x15, 0x3, 0x14, 0x0],
        5 => [b0, 0x1f, 0x3, b3, 0x11],
        6 | 106 => [b0, 0x20, 0x3, b3, 0x11],
        7 => [0x13, 0xc, 0x5, 0x0, 0x0],
        8 => [0x93, 0x25, 0x3, 0x10, 0x0],
        9 | 11 | 109 | 111 | 113 | 114 => [b0, 0x21, 0x3, b3, b4],
        10 => [0x13, 0xa, 0xa, 0x0, 0x40],
        12 => [0x51, 0x0a, 0x0a, 0x0, 0x50],
        13 if scan_ap_num <= 3 => [b0, 0x40, 0x3, b3, b4],
        13 => [b0, 0x21, 0x3, b3, b4],
        14 if scan_ap_num <= 3 => [0x51, 0x30, 0x3, 0x10, 0x50],
        14 => [b0, 0x21, 0x3, b3, b4],
        15 => [0x13, 0xa, 0x3, 0x8, 0x0],
        16 => [0x93, 0x15, 0x3, 0x10, 0x0],
        18 => [0x93, 0x25, 0x3, 0x10, 0x0],
        20 | 120 => [b0, 0x3f, 0x03, b3, 0x10],
        21 => [0x61, 0x25, 0x03, 0x11, 0x11],
        22 | 122 => [b0, 0x25, 0x03, b3, 0x10],
        23 => [0xe3, 0x25, 0x3, 0x31, 0x18],
        24 => [0xe3, 0x15, 0x3, 0x31, 0x18],
        25 | 26 => [0xe3, 0xa, 0x3, 0x31, 0x18],
        27 => [0xe3, 0x25, 0x3, 0x31, 0x98],
        28 => [0x69, 0x25, 0x3, 0x31, 0x0],
        29 => [0xab, 0x1a, 0x1a, 0x1, 0x10],
        30 => [0x51, 0x30, 0x3, 0x10, 0x10],
        31 => [0xd3, 0x1a, 0x1a, 0, 0x58],
        32 => [b0, 0x35, 0x3, b3, b4],
        33 => [b0, 0x35, 0x3, b3, 0x10],
        34 => [0x53, 0x1a, 0x1a, 0x0, 0x10],
        35 => [0x63, 0x1a, 0x1a, 0x0, 0x10],
        36 => [0xd3, 0x12, 0x3, 0x14, 0x50],
        40 => [0x23, 0x18, 0x00, 0x10, 0x24],
        103 => [b0, 0x3a, 0x03, b3, b4],
        105 => [b0, 0x15, 0x3, b3, 0x11],
        132 => [b0, 0x25, 0x03, b3, b4],
        133 => [b0, 0x25, 0x03, b3, 0x11],
        _ => [0x51, 0x1a, 0x1a, 0x0, b4],
    }
}

/// `halbtc8723b1ant_set_fw_ps_tdma`'s AP-mode rewrite: a TDMA with
/// BIT4 but not BIT5 in byte 1 moves to BIT5, byte 5 gains BIT5 and loses
/// BIT6.
pub const fn ap_tdma(mut b: [u8; 5], ap_enable: bool) -> [u8; 5] {
    if ap_enable && b[0] & 0x10 != 0 && b[0] & 0x20 == 0 {
        b[0] = (b[0] & !0x10) | 0x20;
        b[4] = (b[4] | 0x20) & !0x40;
    }
    b
}

/// `halbtc8723b1ant` state.
#[derive(Clone, Debug, Default)]
pub struct B8723b1Ant {
    pub dm: CoexDm,
    pub sta: CoexSta,
    pub st: Statics,
}

type R = Result<(), Error>;

impl B8723b1Ant {
    pub fn new() -> Self {
        Self::default()
    }

    /// `halbtc8723b1ant_updatera_mask`.
    fn updatera_mask<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, dis_rate_mask: u32) {
        self.dm.curra_mask = dis_rate_mask;
        if force || self.dm.prera_mask != self.dm.curra_mask {
            // BTC_SET_ACT_UPDATE_RAMASK.
            cx.btc.bt_info.ra_mask = self.dm.curra_mask;
        }
        self.dm.prera_mask = self.dm.curra_mask;
    }

    /// `btc8723b1ant_auto_rate_fb_retry`.
    fn auto_rate_fb_retry<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, ty: u8) -> R {
        self.dm.cur_arfr_type = ty;
        if force || self.dm.pre_arfr_type != self.dm.cur_arfr_type {
            match ty {
                0 => {
                    cx.write_4byte(0x430, self.dm.backup_arfr_cnt1)?;
                    cx.write_4byte(0x434, self.dm.backup_arfr_cnt2)?;
                }
                1 => {
                    cx.write_4byte(0x430, 0)?;
                    if cx.btc.wifi.under_b_mode() {
                        cx.write_4byte(0x434, 0x0101_0101)?;
                    } else {
                        cx.write_4byte(0x434, 0x0403_0201)?;
                    }
                }
                _ => {}
            }
        }
        self.dm.pre_arfr_type = self.dm.cur_arfr_type;
        Ok(())
    }

    /// `halbtc8723b1ant_retry_limit`.
    fn retry_limit<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, ty: u8) -> R {
        self.dm.cur_retry_limit_type = ty;
        if force || self.dm.pre_retry_limit_type != self.dm.cur_retry_limit_type {
            match ty {
                0 => cx.write_2byte(0x42a, self.dm.backup_retry_limit)?,
                1 => cx.write_2byte(0x42a, 0x0808)?,
                _ => {}
            }
        }
        self.dm.pre_retry_limit_type = self.dm.cur_retry_limit_type;
        Ok(())
    }

    /// `halbtc8723b1ant_ampdu_maxtime`.
    fn ampdu_maxtime<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, ty: u8) -> R {
        self.dm.cur_ampdu_time_type = ty;
        if force || self.dm.pre_ampdu_time_type != self.dm.cur_ampdu_time_type {
            match ty {
                0 => cx.write_1byte(0x456, self.dm.backup_ampdu_max_time)?,
                1 => cx.write_1byte(0x456, 0x38)?,
                _ => {}
            }
        }
        self.dm.pre_ampdu_time_type = self.dm.cur_ampdu_time_type;
        Ok(())
    }

    /// `halbtc8723b1ant_limited_tx`.
    fn limited_tx<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        force: bool,
        ra_masktype: u8,
        arfr_type: u8,
        retry_limit_type: u8,
        ampdu_time_type: u8,
    ) -> R {
        match ra_masktype {
            0 => self.updatera_mask(cx, force, 0x0),
            1 => self.updatera_mask(cx, force, 0x0000_0003),
            2 => self.updatera_mask(cx, force, 0x0001_f1f7),
            _ => {}
        }
        self.auto_rate_fb_retry(cx, force, arfr_type)?;
        self.retry_limit(cx, force, retry_limit_type)?;
        self.ampdu_maxtime(cx, force, ampdu_time_type)
    }

    /// `halbtc8723b1ant_limited_rx` (`force_exec` is unused in Linux).
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

    /// `halbtc8723b1ant_query_bt_info`.
    async fn query_bt_info<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.sta.c2h_bt_info_req_sent = true;
        cx.fill_h2c(H2C_BT_INFO, &[1]).await
    }

    /// `halbtc8723b1ant_monitor_bt_ctr`.
    async fn monitor_bt_ctr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let hp = cx.read_4byte(0x770)?;
        let lp = cx.read_4byte(0x774)?;
        let (hp_tx, hp_rx) = (hp & 0xffff, hp >> 16);
        let (lp_tx, lp_rx) = (lp & 0xffff, lp >> 16);
        self.sta.high_priority_tx = hp_tx;
        self.sta.high_priority_rx = hp_rx;
        self.sta.low_priority_tx = lp_tx;
        self.sta.low_priority_rx = lp_rx;
        if self.sta.low_priority_tx > 1050 && !self.sta.c2h_bt_inquiry_page {
            self.sta.pop_event_cnt = self.sta.pop_event_cnt.wrapping_add(1);
        }
        // Reset the counters.
        cx.write_1byte(0x76e, 0xc)?;
        if hp_tx == 0 && hp_rx == 0 && lp_tx == 0 && lp_rx == 0 {
            self.st.num_of_bt_counter_chk = self.st.num_of_bt_counter_chk.wrapping_add(1);
            if self.st.num_of_bt_counter_chk == 3 {
                self.query_bt_info(cx).await?;
            }
        } else {
            self.st.num_of_bt_counter_chk = 0;
        }
        Ok(())
    }

    /// `halbtc8723b1ant_monitor_wifi_ctr`.
    fn monitor_wifi_ctr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let wifi_busy = cx.btc.wifi.busy;
        let wifi_rssi = cx.wifi_rssi();
        let under_b = cx.btc.wifi.under_b_mode();
        let s = &mut self.sta;
        if s.under_ips {
            s.crc_ok_cck = 0;
            s.crc_ok_11g = 0;
            s.crc_ok_11n = 0;
            s.crc_ok_11n_agg = 0;
            s.crc_err_cck = 0;
            s.crc_err_11g = 0;
            s.crc_err_11n = 0;
            s.crc_err_11n_agg = 0;
        } else {
            s.crc_ok_cck = cx.read_4byte(0xf88)?;
            s.crc_ok_11g = cx.read_2byte(0xf94)?.into();
            s.crc_ok_11n = cx.read_2byte(0xf90)?.into();
            s.crc_ok_11n_agg = cx.read_2byte(0xfb8)?.into();
            s.crc_err_cck = cx.read_4byte(0xf84)?;
            s.crc_err_11g = cx.read_2byte(0xf96)?.into();
            s.crc_err_11n = cx.read_2byte(0xf92)?.into();
            s.crc_err_11n_agg = cx.read_2byte(0xfba)?.into();
        }
        // Reset the CRC counters.
        cx.write_1byte_bitmask(0xf16, 0x1, 0x1)?;
        cx.write_1byte_bitmask(0xf16, 0x1, 0x0)?;
        let s = &mut self.sta;
        let c = &mut self.st.cck_lock_counter;
        let decay = |c: &mut u8| {
            if *c > 0 {
                *c -= 1;
            }
        };
        if wifi_busy && wifi_rssi >= 30 && !under_b {
            let total = s
                .crc_ok_cck
                .wrapping_add(s.crc_ok_11g)
                .wrapping_add(s.crc_ok_11n)
                .wrapping_add(s.crc_ok_11n_agg);
            if self.dm.bt_status.busy() {
                if s.crc_ok_cck > total.wrapping_sub(s.crc_ok_cck) {
                    if *c < 3 {
                        *c += 1;
                    }
                } else {
                    decay(c);
                }
            } else {
                decay(c);
            }
        } else {
            decay(c);
        }
        s.cck_lock = if !s.pre_ccklock { *c >= 3 } else { *c != 0 };
        if s.cck_lock {
            s.cck_ever_lock = true;
        }
        s.pre_ccklock = s.cck_lock;
        Ok(())
    }

    /// `btc8723b1ant_is_wifi_status_changed`.
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
        }
        false
    }

    /// `halbtc8723b1ant_update_bt_link_info`.
    fn update_bt_link_info<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) {
        let bt_hs_on = cx.hs_operation();
        let s = &self.sta;
        let l = &mut cx.btc.bt_link_info;
        l.bt_link_exist = s.bt_link_exist;
        l.sco_exist = s.sco_exist;
        l.a2dp_exist = s.a2dp_exist;
        l.pan_exist = s.pan_exist;
        l.hid_exist = s.hid_exist;
        l.bt_hi_pri_link_exist = s.bt_hi_pri_link_exist;
        if bt_hs_on {
            l.pan_exist = true;
            l.bt_link_exist = true;
        }
        l.sco_only = l.sco_exist && !l.a2dp_exist && !l.pan_exist && !l.hid_exist;
        l.a2dp_only = !l.sco_exist && l.a2dp_exist && !l.pan_exist && !l.hid_exist;
        l.pan_only = !l.sco_exist && !l.a2dp_exist && l.pan_exist && !l.hid_exist;
        l.hid_only = !l.sco_exist && !l.a2dp_exist && !l.pan_exist && l.hid_exist;
    }

    /// `halbtc8723b1ant_bt_auto_report` → `set_bt_auto_report`.
    async fn bt_auto_report<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        force: bool,
        enable: bool,
    ) -> R {
        self.dm.cur_bt_auto_report = enable;
        if !force && self.dm.pre_bt_auto_report == self.dm.cur_bt_auto_report {
            return Ok(());
        }
        cx.fill_h2c(H2C_BT_AUTO_REPORT, &[u8::from(enable)]).await?;
        self.dm.pre_bt_auto_report = self.dm.cur_bt_auto_report;
        Ok(())
    }

    /// `halbtc8723b1ant_low_penalty_ra` →
    /// `btc8723b1ant_set_sw_pen_tx_rate_adapt`.
    async fn low_penalty_ra<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, low: bool) -> R {
        self.dm.cur_low_penalty_ra = low;
        if !force && self.dm.pre_low_penalty_ra == self.dm.cur_low_penalty_ra {
            return Ok(());
        }
        // Normal rate except MCS7/6/5, OFDM54/48/36 retry penalty.
        let cmd = if low {
            [0x6, 0x1, 0x00, 0xf7, 0xf8, 0xf9]
        } else {
            [0x6, 0, 0, 0, 0, 0]
        };
        cx.fill_h2c(H2C_LOW_PENALTY_RA, &cmd).await?;
        self.dm.pre_low_penalty_ra = self.dm.cur_low_penalty_ra;
        Ok(())
    }

    /// `halbtc8723b1ant_coex_table` → `set_coex_table`.
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

    /// `halbtc8723b1ant_coex_table_with_type` (types above 15 write
    /// nothing).
    fn coex_table_with_type<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, ty: u8) -> R {
        self.sta.coex_table_type = ty;
        let Some(&row) = COEX_TABLES.get(usize::from(ty)) else {
            return Ok(());
        };
        let (a, b) = if ty == 4 && self.sta.cck_ever_lock && self.sta.scan_ap_num <= 5 {
            COEX_TABLE_4_CCK_LOCK
        } else {
            row
        };
        self.coex_table(cx, force, a, b, 0x00ff_ffff, 0x3)
    }

    /// `halbtc8723b1ant_ignore_wlan_act` → `set_fw_ignore_wlan_act`.
    async fn ignore_wlan_act<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        force: bool,
        enable: bool,
    ) -> R {
        self.dm.cur_ignore_wlan_act = enable;
        if !force && self.dm.pre_ignore_wlan_act == self.dm.cur_ignore_wlan_act {
            return Ok(());
        }
        cx.fill_h2c(H2C_IGNORE_WLAN_ACT, &[u8::from(enable)])
            .await?;
        self.dm.pre_ignore_wlan_act = self.dm.cur_ignore_wlan_act;
        Ok(())
    }

    /// `halbtc8723b1ant_set_fw_ps_tdma`.
    async fn set_fw_ps_tdma<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, bytes: [u8; 5]) -> R {
        let b = ap_tdma(bytes, cx.btc.wifi.ap_mode);
        self.dm.ps_tdma_para = b;
        cx.fill_h2c(H2C_TDMA, &b).await
    }

    /// `halbtc8723b1ant_lps_rpwm` → `set_lps_rpwm`.
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

    /// `halbtc8723b1ant_sw_mechanism`.
    async fn sw_mechanism<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, low_penalty_ra: bool) -> R {
        self.low_penalty_ra(cx, NORMAL_EXEC, low_penalty_ra).await
    }

    /// `halbtc8723b1ant_set_ant_path`.
    pub async fn set_ant_path<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        ant_pos_type: u8,
        force: bool,
        init_hw_cfg: bool,
        wifi_off: bool,
    ) -> R {
        self.dm.cur_ant_pos_type = ant_pos_type;
        // BTC_GET_BL_EXT_SWITCH is false on rtlwifi.
        let fw_ver = cx.btc.wifi.fw_ver();
        let use_ext_switch = fw_ver < 0xc_0000;
        let main_port = cx.btc.board_info.btdm_ant_pos == BTC_ANTENNA_AT_MAIN_PORT;
        if init_hw_cfg {
            // WiFi TRx mask off.
            cx.set_rf_reg(BTC_RF_A, 0x1, 0xfffff, 0x780).await?;
            // Remove BT calibration (or IQK) delay.
            if fw_ver >= 0x18_0000 {
                cx.fill_h2c(H2C_BT_CALIBRATION, &[1]).await?;
            } else {
                cx.write_1byte(0x765, 0x18)?;
            }
            cx.write_1byte(0x76e, 0x4)?;
            cx.write_1byte_bitmask(0x67, 0x20, 0x0)?;
            cx.write_1byte_bitmask(0x39, 0x8, 0x1)?;
            cx.write_1byte(0x974, 0xff)?;
            cx.write_1byte_bitmask(0x944, 0x3, 0x3)?;
            cx.write_1byte(0x930, 0x77)?;
        } else if wifi_off {
            if fw_ver >= 0x18_0000 {
                cx.fill_h2c(H2C_BT_CALIBRATION, &[1]).await?;
            } else {
                cx.write_1byte(0x765, 0x18)?;
            }
            cx.write_1byte(0x76e, 0x4)?;
            // BTC_GET_BL_WIFI_IS_IN_MP_MODE is false.
            cx.write_1byte_bitmask(0x67, 0x20, 0x0)?;
            let v = cx.read_4byte(0x4c)? & !(1 << 23) & !(1 << 24);
            cx.write_4byte(0x4c, v)?;
        } else {
            if fw_ver >= 0x18_0000 {
                if cx.read_1byte(0x765)? != 0 {
                    cx.fill_h2c(H2C_BT_CALIBRATION, &[0]).await?;
                }
            } else {
                // Wait for BT IQK to finish.
                let mut cnt = 0;
                while cnt <= 20 {
                    let v = cx.read_1byte(0x49d)?;
                    cnt += 1;
                    if v & 1 != 0 {
                        cx.hal.delay_ms(50).await;
                    } else {
                        break;
                    }
                }
                cx.write_1byte(0x765, 0x0)?;
            }
            if cx.read_1byte(0x76e)? != 0xc {
                cx.write_1byte(0x76e, 0xc)?;
            }
            cx.write_1byte_bitmask(0x67, 0x20, 0x1)?;
        }
        let changed = force || self.dm.cur_ant_pos_type != self.dm.pre_ant_pos_type;
        if use_ext_switch {
            if init_hw_cfg {
                // 0x4c[23] = 0, 0x4c[24] = 1: antenna by WL.
                let v = (cx.read_4byte(0x4c)? & !(1 << 23)) | (1 << 24);
                cx.write_4byte(0x4c, v)?;
                cx.write_4byte(0x948, 0x0)?;
                let cmd = if main_port { [0, 1] } else { [1, 1] };
                cx.fill_h2c(H2C_ANT_SEL, &cmd).await?;
            }
            if changed {
                let v = match (ant_pos_type, main_port) {
                    (BTC_ANT_PATH_BT, true) => 0x2,
                    (BTC_ANT_PATH_BT, false) => 0x1,
                    // BTC_ANT_PATH_WIFI, BTC_ANT_PATH_PTA and default.
                    (_, true) => 0x1,
                    (_, false) => 0x2,
                };
                cx.write_1byte_bitmask(0x92c, 0x3, v)?;
            }
        } else {
            if init_hw_cfg {
                // 0x4c[23] = 1, 0x4c[24] = 0: antenna by 0x64.
                let v = (cx.read_4byte(0x4c)? | (1 << 23)) & !(1 << 24);
                cx.write_4byte(0x4c, v)?;
                cx.write_1byte_bitmask(0x64, 0x1, 0x0)?;
                let cmd = if main_port { [0, 0] } else { [1, 0] };
                cx.fill_h2c(H2C_ANT_SEL, &cmd).await?;
            }
            if changed {
                let v = match (ant_pos_type, main_port) {
                    (BTC_ANT_PATH_WIFI, true) => 0x0,
                    (BTC_ANT_PATH_WIFI, false) => 0x280,
                    (BTC_ANT_PATH_BT, true) => 0x280,
                    (BTC_ANT_PATH_BT, false) => 0x0,
                    (_, true) => 0x200,
                    (_, false) => 0x80,
                };
                cx.write_4byte(0x948, v)?;
            }
        }
        self.dm.pre_ant_pos_type = self.dm.cur_ant_pos_type;
        Ok(())
    }

    /// `halbtc8723b1ant_ps_tdma`.
    pub async fn ps_tdma<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        mut force: bool,
        turn_on: bool,
        ty: u8,
    ) -> R {
        self.dm.cur_ps_tdma_on = turn_on;
        self.dm.cur_ps_tdma = ty;
        let wifi_busy = cx.btc.wifi.busy;
        if wifi_busy != self.st.tdma_pre_wifi_busy {
            force = true;
            self.st.tdma_pre_wifi_busy = wifi_busy;
        }
        if !force
            && self.dm.pre_ps_tdma_on == self.dm.cur_ps_tdma_on
            && self.dm.pre_ps_tdma == self.dm.cur_ps_tdma
        {
            return Ok(());
        }
        let adj = wifi_duration_adjust(self.sta.scan_ap_num, self.sta.a2dp_bit_pool);
        let l = cx.btc.bt_link_info;
        let bytes = ps_tdma_bytes(
            turn_on,
            ty,
            self.sta.force_lps_on,
            adj,
            l.slave_role && l.a2dp_exist,
            self.sta.scan_ap_num,
        );
        self.set_fw_ps_tdma(cx, bytes).await?;
        if !turn_on && ty == 8 {
            // TDMA off: antenna to PTA.
            self.set_ant_path(cx, BTC_ANT_PATH_PTA, FORCE_EXEC, false, false)
                .await?;
        }
        // BTC_SET_U1_RSSI_ADJ_VAL_FOR_1ANT_COEX_TYPE (always 0 here).
        cx.btc.bt_info.rssi_adjust_for_1ant_coex_type = 0;
        self.dm.pre_ps_tdma_on = self.dm.cur_ps_tdma_on;
        self.dm.pre_ps_tdma = self.dm.cur_ps_tdma;
        Ok(())
    }

    fn reset_adj(&mut self) {
        self.st.up = 0;
        self.st.dn = 0;
        self.st.m = 1;
        self.st.n = 3;
        self.st.wait_count = 0;
    }

    async fn tdma_to<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: u8) -> R {
        self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
        self.dm.ps_tdma_du_adj_type = ty;
        Ok(())
    }

    /// `btc8723b1ant_tdma_dur_adj_for_acl`.
    async fn tdma_dur_adj_for_acl<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        wifi_status: WifiStatus,
    ) -> R {
        if matches!(
            wifi_status,
            WifiStatus::NonConnectedAssoAuthScan
                | WifiStatus::ConnectedScan
                | WifiStatus::ConnectedSpecialPkt
        ) {
            if !matches!(self.dm.cur_ps_tdma, 1 | 2 | 3 | 9) {
                self.tdma_to(cx, 9).await?;
                self.reset_adj();
            }
            return Ok(());
        }
        if !self.dm.auto_tdma_adjust {
            self.dm.auto_tdma_adjust = true;
            self.tdma_to(cx, 2).await?;
            self.reset_adj();
            return Ok(());
        }
        let mut retry_count = self.sta.bt_retry_cnt;
        if self.sta.low_priority_tx > 1050 || self.sta.low_priority_rx > 1250 {
            retry_count = retry_count.wrapping_add(1);
        }
        let mut result = 0;
        let s = &mut self.st;
        s.wait_count += 1;
        if retry_count == 0 {
            // No retry in the last 2 s.
            s.up += 1;
            s.dn -= 1;
            if s.dn <= 0 {
                s.dn = 0;
            }
            if s.up >= s.n {
                s.wait_count = 0;
                s.n = 3;
                s.up = 0;
                s.dn = 0;
                result = 1;
            }
        } else if retry_count <= 3 {
            s.up -= 1;
            s.dn += 1;
            if s.up <= 0 {
                s.up = 0;
            }
            if s.dn == 2 {
                if s.wait_count <= 2 {
                    s.m += 1;
                } else {
                    s.m = 1;
                }
                if s.m >= 20 {
                    s.m = 20;
                }
                s.n = 3 * s.m;
                s.up = 0;
                s.dn = 0;
                s.wait_count = 0;
                result = -1;
            }
        } else {
            if s.wait_count == 1 {
                s.m += 1;
            } else {
                s.m = 1;
            }
            if s.m >= 20 {
                s.m = 20;
            }
            s.n = 3 * s.m;
            s.up = 0;
            s.dn = 0;
            s.wait_count = 0;
            result = -1;
        }
        if result == -1 {
            match self.dm.cur_ps_tdma {
                1 => self.tdma_to(cx, 2).await?,
                2 => self.tdma_to(cx, 9).await?,
                9 => self.tdma_to(cx, 11).await?,
                _ => {}
            }
        } else if result == 1 {
            match self.dm.cur_ps_tdma {
                11 => self.tdma_to(cx, 9).await?,
                9 => self.tdma_to(cx, 2).await?,
                2 => self.tdma_to(cx, 1).await?,
                _ => {}
            }
        }
        if !matches!(self.dm.cur_ps_tdma, 1 | 2 | 9 | 11) {
            // Recover to the previous adjust type.
            let ty = self.dm.ps_tdma_du_adj_type;
            self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
        }
        Ok(())
    }

    /// `halbtc8723b1ant_ps_tdma_chk_pwr_save`.
    async fn ps_tdma_chk_pwr_save<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, new_ps_state: bool) -> R {
        let lps_mode = cx.lps_mode();
        // Already under LPS and leaving it, or entering it from native:
        // TDMA off first.
        if (lps_mode != 0) != new_ps_state {
            self.ps_tdma(cx, NORMAL_EXEC, false, 0).await?;
        }
        Ok(())
    }

    /// `halbtc8723b1ant_power_save_state`.
    async fn power_save_state<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        ps: PowerSave,
        lps: u8,
        rpwm: u8,
    ) -> R {
        match ps {
            PowerSave::WifiNative => {
                cx.disable_low_power(false);
                cx.normal_lps().await?;
                self.sta.force_lps_on = false;
            }
            PowerSave::LpsOn => {
                self.ps_tdma_chk_pwr_save(cx, true).await?;
                self.lps_rpwm(cx, NORMAL_EXEC, lps, rpwm);
                cx.disable_low_power(true);
                // Power save must be executed before TDMA.
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

    /// `halbtc8723b1ant_action_wifi_only`.
    async fn action_wifi_only<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.coex_table_with_type(cx, FORCE_EXEC, 0)?;
        self.ps_tdma(cx, FORCE_EXEC, false, 8).await?;
        self.set_ant_path(cx, BTC_ANT_PATH_PTA, FORCE_EXEC, false, false)
            .await
    }

    /// `halbtc8723b1ant_monitor_bt_enable_disable`.
    async fn monitor_bt_enable_disable<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let s = &self.sta;
        let all = |v: u32| {
            s.high_priority_tx == v
                && s.high_priority_rx == v
                && s.low_priority_tx == v
                && s.low_priority_rx == v
        };
        // A disabled BT reads all-zero (or all-0xffff) priority counters.
        let bt_active = !all(0) && !all(0xffff);
        let bt_disabled = if bt_active {
            self.st.bt_disable_cnt = 0;
            false
        } else {
            self.st.bt_disable_cnt = self.st.bt_disable_cnt.wrapping_add(1);
            self.st.bt_disable_cnt >= 2
        };
        if self.sta.bt_disabled != bt_disabled {
            self.sta.bt_disabled = bt_disabled;
            // BTC_SET_BL_BT_DISABLE.
            cx.btc.bt_info.bt_disabled = bt_disabled;
            if bt_disabled {
                self.action_wifi_only(cx).await?;
                cx.leave_lps().await?;
                cx.normal_lps().await?;
            }
        }
        Ok(())
    }

    /// `halbtc8723b1ant_action_bt_whck_test`.
    async fn action_bt_whck_test<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 8).await?;
        self.set_ant_path(cx, BTC_ANT_PATH_PTA, NORMAL_EXEC, false, false)
            .await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)
    }

    /// `halbtc8723b1ant_action_wifi_multiport`.
    async fn action_wifi_multiport<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ps_tdma(cx, NORMAL_EXEC, false, 8).await?;
        self.set_ant_path(cx, BTC_ANT_PATH_PTA, NORMAL_EXEC, false, false)
            .await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 2)
    }

    /// `halbtc8723b1ant_action_hs`.
    async fn action_hs<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.ps_tdma(cx, NORMAL_EXEC, true, 5).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 2)
    }

    /// The `power_save_state(NATIVE)`, TDMA-off(8), PTA and coex-table
    /// tail several actions share.
    async fn native_tdma_off_pta<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        table: u8,
        table_force: bool,
    ) -> R {
        self.ps_tdma(cx, NORMAL_EXEC, false, 8).await?;
        self.set_ant_path(cx, BTC_ANT_PATH_PTA, NORMAL_EXEC, false, false)
            .await?;
        self.coex_table_with_type(cx, table_force, table)
    }

    /// `halbtc8723b1ant_action_bt_inquiry`.
    async fn action_bt_inquiry<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let wifi_connected = cx.btc.wifi.connected();
        let wifi_busy = cx.btc.wifi.busy;
        // BTC_SET_BL_BT_TRAFFIC_BUSY(false).
        cx.btc.bt_info.bt_busy = false;
        let l = cx.btc.bt_link_info;
        if self.sta.bt_abnormal_scan {
            self.ps_tdma(cx, NORMAL_EXEC, true, 33).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 7)
        } else if !wifi_connected && !self.sta.wifi_is_high_pri_task {
            self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                .await?;
            self.native_tdma_off_pta(cx, 0, NORMAL_EXEC).await
        } else if l.sco_exist || l.hid_exist || l.a2dp_exist || l.pan_exist || wifi_busy {
            // SCO/HID/A2DP busy, or PAN / Wi-Fi busy: identical in Linux.
            self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                .await?;
            let ty = if self.sta.c2h_bt_remote_name_req {
                33
            } else {
                32
            };
            self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 4)
        } else {
            self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                .await?;
            self.native_tdma_off_pta(cx, 7, NORMAL_EXEC).await
        }
    }

    /// `btc8723b1ant_act_bt_sco_hid_only_busy`.
    async fn act_bt_sco_hid_only_busy<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        _wifi_status: WifiStatus,
    ) -> R {
        // SCO uses TDMA 5, HID 6; both coex table 5.
        let ty = if cx.btc.bt_link_info.sco_exist { 5 } else { 6 };
        self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 5)
    }

    /// `halbtc8723b1ant_action_wifi_connected_bt_acl_busy`.
    async fn action_wifi_connected_bt_acl_busy<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        wifi_status: WifiStatus,
    ) -> R {
        cx.btc.bt_link_info.slave_role = self.sta.low_priority_rx >= 950 && !self.sta.under_ips;
        let l = cx.btc.bt_link_info;
        if l.hid_only {
            self.act_bt_sco_hid_only_busy(cx, wifi_status).await?;
            self.dm.auto_tdma_adjust = false;
            return Ok(());
        }
        if l.a2dp_only {
            if wifi_status == WifiStatus::ConnectedIdle {
                self.ps_tdma(cx, NORMAL_EXEC, true, 32).await?;
                self.coex_table_with_type(cx, NORMAL_EXEC, 4)?;
                self.dm.auto_tdma_adjust = false;
            } else {
                self.tdma_dur_adj_for_acl(cx, wifi_status).await?;
                self.coex_table_with_type(cx, NORMAL_EXEC, 1)?;
                self.dm.auto_tdma_adjust = true;
            }
            return Ok(());
        }
        // Linux: `(A2DP && PAN) || (HID && A2DP && PAN)`, i.e. A2DP + PAN.
        let ty = if l.a2dp_exist && l.pan_exist {
            13
        } else if l.hid_exist && l.a2dp_exist {
            14
        } else if l.pan_only || (l.hid_exist && l.pan_exist) {
            3
        } else {
            33
        };
        self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 4)?;
        self.dm.auto_tdma_adjust = false;
        Ok(())
    }

    /// `btc8723b1ant_action_wifi_not_conn`.
    async fn action_wifi_not_conn<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        // TDMA forced off (8).
        self.ps_tdma(cx, FORCE_EXEC, false, 8).await?;
        self.set_ant_path(cx, BTC_ANT_PATH_PTA, NORMAL_EXEC, false, false)
            .await?;
        self.coex_table_with_type(cx, NORMAL_EXEC, 0)
    }

    /// `btc8723b1ant_action_wifi_not_conn_scan` (`not_conn == true`) and
    /// `btc8723b1ant_action_wifi_conn_scan` (identical but for the
    /// non-A2DP/non-PAN ACL coex table: 1 vs 4).
    async fn action_wifi_scan<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, not_conn: bool) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        let l = cx.btc.bt_link_info;
        if self.dm.bt_status == BtStatus::AclBusy {
            let (ty, table) = if l.a2dp_exist {
                (32, 4)
            } else if l.pan_exist {
                (22, 4)
            } else {
                (20, if not_conn { 1 } else { 4 })
            };
            self.ps_tdma(cx, NORMAL_EXEC, true, ty).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, table)
        } else if self.dm.bt_status.sco_busy() {
            self.act_bt_sco_hid_only_busy(cx, WifiStatus::ConnectedScan)
                .await
        } else {
            // Bryant add
            self.native_tdma_off_pta(cx, 2, NORMAL_EXEC).await
        }
    }

    /// `btc8723b1ant_act_wifi_not_conn_asso_auth`.
    async fn act_wifi_not_conn_asso_auth<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        let l = cx.btc.bt_link_info;
        if l.sco_exist || l.hid_exist || l.a2dp_exist {
            self.ps_tdma(cx, NORMAL_EXEC, true, 32).await?;
            self.coex_table_with_type(cx, FORCE_EXEC, 4)
        } else if l.pan_exist {
            self.ps_tdma(cx, NORMAL_EXEC, true, 20).await?;
            self.coex_table_with_type(cx, FORCE_EXEC, 4)
        } else {
            self.native_tdma_off_pta(cx, 2, FORCE_EXEC).await
        }
    }

    /// `halbtc8723b1ant_action_wifi_connected_special_packet`.
    async fn action_wifi_connected_special_packet<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let wifi_busy = cx.btc.wifi.busy;
        let l = cx.btc.bt_link_info;
        // No special packet process for both Wi-Fi and BT very busy.
        if wifi_busy && (l.pan_exist || self.sta.num_of_profile >= 2) {
            return Ok(());
        }
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        if l.sco_exist || l.hid_exist {
            self.ps_tdma(cx, NORMAL_EXEC, true, 32).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 5)
        } else if l.a2dp_exist {
            self.ps_tdma(cx, NORMAL_EXEC, true, 32).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 4)
        } else if l.pan_exist {
            self.ps_tdma(cx, NORMAL_EXEC, true, 20).await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 4)
        } else {
            self.native_tdma_off_pta(cx, 2, NORMAL_EXEC).await
        }
    }

    /// `halbtc8723b1ant_action_wifi_connected`.
    async fn action_wifi_connected<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let w = cx.btc.wifi;
        if w.in_4way {
            return self.action_wifi_connected_special_packet(cx).await;
        }
        // BTC_GET_BL_WIFI_LINK and BTC_GET_BL_WIFI_ROAM are both LINKING.
        if w.scanning || w.linking {
            if w.scanning {
                return self.action_wifi_scan(cx, false).await;
            }
            return self.action_wifi_connected_special_packet(cx).await;
        }
        let ap_enable = w.ap_mode;
        let wifi_busy = w.busy;
        let l = cx.btc.bt_link_info;
        // Power save state.
        if !ap_enable && self.dm.bt_status == BtStatus::AclBusy && !l.hid_only {
            if l.a2dp_only {
                if !wifi_busy || self.sta.scan_ap_num >= WIFI_NOISY_THRESH {
                    self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                        .await?;
                } else {
                    self.power_save_state(cx, PowerSave::LpsOn, 0x50, 0x4)
                        .await?;
                }
            } else if !self.sta.pan_exist && !self.sta.a2dp_exist && !self.sta.hid_exist {
                self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                    .await?;
            } else {
                self.power_save_state(cx, PowerSave::LpsOn, 0x50, 0x4)
                    .await?;
            }
        } else {
            self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                .await?;
        }
        // TDMA.
        let status = if wifi_busy {
            WifiStatus::ConnectedBusy
        } else {
            WifiStatus::ConnectedIdle
        };
        if self.dm.bt_status == BtStatus::AclBusy {
            self.action_wifi_connected_bt_acl_busy(cx, status).await
        } else if self.dm.bt_status.sco_busy() {
            self.act_bt_sco_hid_only_busy(cx, status).await
        } else if !wifi_busy {
            self.native_tdma_off_pta(cx, 2, NORMAL_EXEC).await
        } else {
            self.ps_tdma(cx, NORMAL_EXEC, true, 32).await?;
            self.set_ant_path(cx, BTC_ANT_PATH_PTA, NORMAL_EXEC, false, false)
                .await?;
            self.coex_table_with_type(cx, NORMAL_EXEC, 4)
        }
    }

    /// `halbtc8723b1ant_run_coexist_mechanism`.
    async fn run_coexist_mechanism<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if cx.btc.manual_control || cx.btc.stop_coex_dm || self.sta.under_ips {
            return Ok(());
        }
        if self.sta.bt_whck_test {
            return self.action_bt_whck_test(cx).await;
        }
        // BTC_SET_BL_INC_SCAN_DEV_NUM.
        cx.btc.bt_info.increase_scan_dev_num = self.dm.bt_status.busy();
        let w = cx.btc.wifi;
        let wifi_connected = w.connected();
        let wifi_busy = w.busy;
        let link_status = w.link_status();
        let num_of_wifi_link = link_status >> 16;
        let l = cx.btc.bt_link_info;
        if num_of_wifi_link >= 2 || link_status & WIFI_P2P_GO_CONNECTED != 0 {
            let miracast_plus_bt = if l.bt_link_exist {
                self.limited_tx(cx, NORMAL_EXEC, 1, 1, 0, 1)?;
                true
            } else {
                self.limited_tx(cx, NORMAL_EXEC, 0, 0, 0, 0)?;
                false
            };
            cx.btc.bt_info.miracast_plus_bt = miracast_plus_bt;
            self.limited_rx(cx, NORMAL_EXEC, false, false, 5);
            if (l.a2dp_exist || wifi_busy) && self.sta.c2h_bt_inquiry_page {
                return self.action_bt_inquiry(cx).await;
            }
            return self.action_wifi_multiport(cx).await;
        }
        cx.btc.bt_info.miracast_plus_bt = false;
        let wifi_bw = w.bw();
        if l.bt_link_exist && wifi_connected {
            self.limited_tx(cx, NORMAL_EXEC, 1, 1, 0, 1)?;
            let iot_peer = cx.iot_peer();
            if iot_peer != IOT_PEER_CISCO && iot_peer != IOT_PEER_BROADCOM {
                self.limited_rx(cx, NORMAL_EXEC, l.sco_exist, false, 0x5);
            } else if l.sco_exist {
                self.limited_rx(cx, NORMAL_EXEC, true, false, 0x5);
            } else if wifi_bw == WifiBw::Ht40 {
                self.limited_rx(cx, NORMAL_EXEC, false, true, 0x10);
            } else {
                self.limited_rx(cx, NORMAL_EXEC, false, true, 0x8);
            }
            self.sw_mechanism(cx, true).await?;
        } else {
            self.limited_tx(cx, NORMAL_EXEC, 0, 0, 0, 0)?;
            self.limited_rx(cx, NORMAL_EXEC, false, false, 0x5);
            self.sw_mechanism(cx, false).await?;
        }
        if self.sta.c2h_bt_inquiry_page {
            return self.action_bt_inquiry(cx).await;
        } else if cx.hs_operation() {
            return self.action_hs(cx).await;
        }
        if !wifi_connected {
            if w.scanning || w.linking {
                if w.scanning {
                    self.action_wifi_scan(cx, true).await
                } else {
                    self.act_wifi_not_conn_asso_auth(cx).await
                }
            } else {
                self.action_wifi_not_conn(cx).await
            }
        } else {
            self.action_wifi_connected(cx).await
        }
    }

    /// `halbtc8723b1ant_init_coex_dm`.
    async fn init_coex_dm_inner<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        // SW mechanism.
        self.sw_mechanism(cx, false).await?;
        self.sta.pop_event_cnt = 0;
        Ok(())
    }

    /// `halbtc8723b1ant_init_hw_config` (`backup` is unused in Linux).
    async fn init_hw_config_inner<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        _backup: bool,
        wifi_only: bool,
    ) -> R {
        self.sta.cut_version = (cx.read_1byte(0xf1)? & 0xf0) >> 4;
        // 0x550[3] = 1: enable TBTT interrupt.
        cx.write_1byte_bitmask(0x550, 0x8, 0x1)?;
        // 0x790[5:0] = 0x5.
        cx.write_1byte(0x790, 0x5)?;
        // Enable counter statistics.
        cx.write_1byte(0x778, 0x1)?;
        cx.write_1byte_bitmask(0x40, 0x20, 0x1)?;
        // Antenna config.
        self.ps_tdma(cx, FORCE_EXEC, false, 8).await?;
        let path = if wifi_only {
            BTC_ANT_PATH_WIFI
        } else {
            BTC_ANT_PATH_BT
        };
        self.set_ant_path(cx, path, FORCE_EXEC, true, false).await?;
        // PTA parameter.
        self.coex_table_with_type(cx, FORCE_EXEC, 0)?;
        // Linux reads these for its debug print.
        cx.read_4byte(0x948)?;
        cx.read_1byte(0x765)?;
        cx.read_1byte(0x67)?;
        Ok(())
    }

    /// The `num_of_wifi_link >= 2` prologue of the scan / connect /
    /// special-packet notifies; true when it handled the notify.
    async fn multiport<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<bool, Error> {
        if cx.btc.wifi.link_status() >> 16 >= 2 {
            self.limited_tx(cx, NORMAL_EXEC, 0, 0, 0, 0)?;
            self.limited_rx(cx, NORMAL_EXEC, false, false, 5);
            self.action_wifi_multiport(cx).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// The inquiry-page / HS prologue of the scan / connect / special
    /// packet notifies; true when it handled the notify.
    async fn inquiry_or_hs<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<bool, Error> {
        if self.sta.c2h_bt_inquiry_page {
            self.action_bt_inquiry(cx).await?;
            return Ok(true);
        } else if cx.hs_operation() {
            self.action_hs(cx).await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `ex_btc8723b1ant_rf_status_notify` (`BTC_RF_ON` = true).
    pub async fn rf_status_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, rf_on: bool) -> R {
        if rf_on {
            cx.btc.stop_coex_dm = false;
            return Ok(());
        }
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ps_tdma(cx, FORCE_EXEC, false, 0).await?;
        self.set_ant_path(cx, BTC_ANT_PATH_BT, FORCE_EXEC, false, true)
            .await?;
        self.ignore_wlan_act(cx, FORCE_EXEC, true).await?;
        cx.btc.stop_coex_dm = true;
        cx.read_4byte(0x948)?;
        cx.read_1byte(0x765)?;
        cx.read_1byte(0x67)?;
        cx.read_1byte(0x76e)?;
        Ok(())
    }
}

impl super::btc::Algorithm for B8723b1Ant {
    /// `ex_btc8723b1ant_power_on_setting`.
    async fn power_on_setting<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        cx.btc.stop_coex_dm = true;
        cx.write_1byte(0x67, 0x20)?;
        // Enable BB, REG_SYS_FUNC_EN such that we can write 0x948
        // correctly.
        let v = cx.read_2byte(0x2)?;
        cx.write_2byte(0x2, v | 0x3)?;
        // Set GRAN_BT = 1.
        cx.write_1byte(0x765, 0x18)?;
        // WLAN_TX_PKT / BT_TX / ... counters: set WLAN_ACT = 0.
        cx.write_1byte(0x76e, 0x4)?;
        // S0 or S1 setting and local register setting (by the BT
        // firmware: 0x38 / 0x384 bit0 = 1 for S0).
        let mut u8tmp = 0u8;
        if cx.btc.chip_interface == super::btc::ChipInterface::Usb {
            // Fixed at S0 for USB.
            cx.write_4byte(0x948, 0x0)?;
            u8tmp |= 0x1;
            cx.write_local_reg_1byte(0xfe08, u8tmp)?;
            cx.btc.board_info.btdm_ant_pos = BTC_ANTENNA_AT_AUX_PORT;
        } else {
            // BTC_SET_ACT_ANTPOSREGRISTRY_CTRL has no rtlwifi handler.
            match cx.btc.board_info.single_ant_path {
                0 => {
                    // Main (S1).
                    cx.write_4byte(0x948, 0x280)?;
                    cx.btc.board_info.btdm_ant_pos = BTC_ANTENNA_AT_MAIN_PORT;
                }
                1 => {
                    // Aux (S0).
                    cx.write_4byte(0x948, 0x0)?;
                    u8tmp |= 0x1;
                    cx.btc.board_info.btdm_ant_pos = BTC_ANTENNA_AT_AUX_PORT;
                }
                _ => {}
            }
            match cx.btc.chip_interface {
                super::btc::ChipInterface::Pci => cx.write_local_reg_1byte(0x384, u8tmp)?,
                super::btc::ChipInterface::Sdio => cx.write_local_reg_1byte(0x60, u8tmp)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// `ex_btc8723b1ant_init_hwconfig`.
    async fn init_hw_config<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, wifi_only: bool) -> R {
        self.init_hw_config_inner(cx, true, wifi_only).await?;
        cx.btc.stop_coex_dm = false;
        Ok(())
    }

    /// `ex_btc8723b1ant_init_coex_dm`.
    async fn init_coex_dm<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        cx.btc.stop_coex_dm = false;
        self.init_coex_dm_inner(cx).await?;
        self.query_bt_info(cx).await
    }

    /// `ex_btc8723b1ant_ips_notify`.
    async fn ips_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Ips) -> R {
        if cx.btc.manual_control || cx.btc.stop_coex_dm {
            return Ok(());
        }
        match ty {
            Ips::Enter => {
                self.sta.under_ips = true;
                self.set_ant_path(cx, BTC_ANT_PATH_BT, FORCE_EXEC, false, true)
                    .await?;
                // Set PS TDMA for the BT antenna.
                self.ps_tdma(cx, NORMAL_EXEC, false, 0).await?;
                self.coex_table_with_type(cx, NORMAL_EXEC, 0)
            }
            Ips::Leave => {
                self.sta.under_ips = false;
                self.init_hw_config_inner(cx, false, false).await?;
                self.init_coex_dm_inner(cx).await?;
                self.query_bt_info(cx).await
            }
        }
    }

    /// `ex_btc8723b1ant_lps_notify`.
    async fn lps_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Lps) -> R {
        if cx.btc.manual_control || cx.btc.stop_coex_dm {
            return Ok(());
        }
        self.sta.under_lps = ty == Lps::Enable;
        Ok(())
    }

    /// `ex_btc8723b1ant_scan_notify`.
    async fn scan_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Scan) -> R {
        if cx.btc.manual_control || cx.btc.stop_coex_dm {
            return Ok(());
        }
        if ty == Scan::Start {
            self.sta.wifi_is_high_pri_task = true;
            // Force antenna setup for no scan result issue.
            self.ps_tdma(cx, FORCE_EXEC, false, 8).await?;
            self.set_ant_path(cx, BTC_ANT_PATH_PTA, FORCE_EXEC, false, false)
                .await?;
            cx.read_4byte(0x948)?;
            cx.read_1byte(0x765)?;
            cx.read_1byte(0x67)?;
        } else {
            self.sta.wifi_is_high_pri_task = false;
            // BTC_GET_U1_AP_NUM.
            self.sta.scan_ap_num = cx.btc.wifi.ap_num;
        }
        if self.sta.bt_disabled {
            return Ok(());
        }
        let wifi_connected = cx.btc.wifi.connected();
        self.query_bt_info(cx).await?;
        if self.multiport(cx).await? || self.inquiry_or_hs(cx).await? {
            return Ok(());
        }
        match (ty, wifi_connected) {
            (Scan::Start, false) => self.action_wifi_scan(cx, true).await,
            (Scan::Start, true) => self.action_wifi_scan(cx, false).await,
            (Scan::Finish, false) => self.action_wifi_not_conn(cx).await,
            (Scan::Finish, true) => self.action_wifi_connected(cx).await,
            (Scan::Start2G, _) => Ok(()),
        }
    }

    /// `ex_btc8723b1ant_connect_notify`.
    async fn connect_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Associate) -> R {
        if cx.btc.manual_control || cx.btc.stop_coex_dm || self.sta.bt_disabled {
            return Ok(());
        }
        if ty == Associate::Start {
            self.sta.wifi_is_high_pri_task = true;
            // Force antenna setup for no scan result issue.
            self.ps_tdma(cx, FORCE_EXEC, false, 8).await?;
            self.set_ant_path(cx, BTC_ANT_PATH_PTA, FORCE_EXEC, false, false)
                .await?;
            self.dm.arp_cnt = 0;
        } else {
            self.sta.wifi_is_high_pri_task = false;
        }
        if self.multiport(cx).await? || self.inquiry_or_hs(cx).await? {
            return Ok(());
        }
        match ty {
            Associate::Start => self.act_wifi_not_conn_asso_auth(cx).await,
            Associate::Finish => {
                if !cx.btc.wifi.connected() {
                    self.action_wifi_not_conn(cx).await
                } else {
                    self.action_wifi_connected(cx).await
                }
            }
            _ => Ok(()),
        }
    }

    /// `ex_btc8723b1ant_media_status_notify`.
    async fn media_status_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Media) -> R {
        if cx.btc.manual_control || cx.btc.stop_coex_dm || self.sta.bt_disabled {
            return Ok(());
        }
        if ty == Media::Connect {
            // Force antenna setup for no scan result issue.
            self.ps_tdma(cx, FORCE_EXEC, false, 8).await?;
            self.set_ant_path(cx, BTC_ANT_PATH_PTA, FORCE_EXEC, false, false)
                .await?;
            // Set CCK Tx/Rx high priority.
            cx.write_1byte(0x6cd, 0x00)?;
            if cx.btc.wifi.under_b_mode() {
                cx.write_1byte(0x6cf, 0x00)?;
            } else {
                cx.write_1byte(0x6cf, 0x10)?;
            }
            self.dm.backup_arfr_cnt1 = cx.read_4byte(0x430)?;
            self.dm.backup_arfr_cnt2 = cx.read_4byte(0x434)?;
            self.dm.backup_retry_limit = cx.read_2byte(0x42a)?;
            self.dm.backup_ampdu_max_time = cx.read_1byte(0x456)?;
        } else {
            self.dm.arp_cnt = 0;
            // CCK Tx/Rx high priority off.
            cx.write_1byte(0x6cd, 0x0)?;
            cx.write_1byte(0x6cf, 0x0)?;
            self.sta.cck_ever_lock = false;
        }
        // Inform the BT firmware of the Wi-Fi channel.
        let chnl = cx.btc.wifi.central_chnl();
        let mut h2c = [0u8; 3];
        if ty == Media::Connect && chnl <= 14 {
            h2c[1] = chnl;
            h2c[2] = if cx.btc.wifi.bw() == WifiBw::Ht40 {
                0x30
            } else {
                0x20
            };
        }
        self.dm.wifi_chnl_info = h2c;
        cx.fill_h2c(H2C_WIFI_CHNL, &h2c).await
    }

    /// `ex_btc8723b1ant_special_packet_notify`.
    async fn special_packet_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Packet) -> R {
        let under_4way = cx.btc.wifi.in_4way;
        if cx.btc.manual_control || cx.btc.stop_coex_dm || self.sta.bt_disabled {
            return Ok(());
        }
        self.sta.wifi_is_high_pri_task = match ty {
            Packet::Arp => {
                self.dm.arp_cnt = self.dm.arp_cnt.wrapping_add(1);
                self.dm.arp_cnt < 10 || under_4way
            }
            Packet::Dhcp | Packet::Eapol => true,
            Packet::Unknown => false,
        };
        if self.multiport(cx).await? {
            return Ok(());
        }
        self.sta.special_pkt_period_cnt = 0;
        if self.inquiry_or_hs(cx).await? {
            return Ok(());
        }
        if matches!(ty, Packet::Dhcp | Packet::Eapol) {
            self.action_wifi_connected_special_packet(cx).await?;
        }
        Ok(())
    }

    /// `ex_btc8723b1ant_bt_info_notify`.
    async fn bt_info_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, buf: &[u8]) -> R {
        if buf.is_empty() {
            return Ok(());
        }
        self.sta.c2h_bt_info_req_sent = false;
        let mut src = usize::from(buf[0] & 0xf);
        if src >= BT_INFO_SRC_MAX {
            src = BT_INFO_SRC_WIFI_FW;
        }
        self.sta.bt_info_c2h_cnt[src] = self.sta.bt_info_c2h_cnt[src].wrapping_add(1);
        // `bt_info_c2h[src]` holds 10 bytes; Linux writes `length` bytes.
        let n = buf.len().min(10);
        self.sta.bt_info_c2h[src][..n].copy_from_slice(&buf[..n]);
        let mut bt_info = buf.get(1).copied().unwrap_or(0);
        self.sta.bt_whck_test = bt_info == 0xff;
        if src != BT_INFO_SRC_WIFI_FW {
            let c = self.sta.bt_info_c2h[src];
            self.sta.bt_retry_cnt = c[2] & 0xf;
            if self.sta.bt_retry_cnt >= 1 {
                self.sta.pop_event_cnt = self.sta.pop_event_cnt.wrapping_add(1);
            }
            self.sta.c2h_bt_remote_name_req = c[2] & 0x20 != 0;
            self.sta.bt_rssi = c[3].wrapping_mul(2).wrapping_sub(90);
            self.sta.bt_info_ext = c[4];
            self.sta.a2dp_bit_pool = if c[1] == 0x49 { c[6] } else { 0 };
            self.sta.bt_tx_rx_mask = c[2] & 0x40 != 0;
            // BTC_SET_BL_BT_TX_RX_MASK.
            cx.btc.bt_info.bt_tx_rx_mask = self.sta.bt_tx_rx_mask;
            if !self.sta.bt_tx_rx_mask {
                // BT into is responded by BT firmware and BT RF REG 0x3C
                // != 0x15 ⇒ need to switch BT TRx mask.
                cx.set_bt_reg(BtReg::Rf, 0x3c, 0x15).await?;
                // BT TRx mask off.
                cx.set_bt_reg(BtReg::Rf, 0x2c, 0x7c44).await?;
                cx.set_bt_reg(BtReg::Rf, 0x30, 0x7c44).await?;
            }
            // Here we need to resend some Wi-Fi info to BT because the BT
            // was reset and lost the info.
            if self.sta.bt_info_ext & 0x2 != 0 {
                let ty = if cx.btc.wifi.connected() {
                    Media::Connect
                } else {
                    Media::Disconnect
                };
                super::btc::Algorithm::media_status_notify(self, cx, ty).await?;
            }
            if self.sta.bt_info_ext & 0x8 != 0 && !cx.btc.manual_control && !cx.btc.stop_coex_dm {
                self.ignore_wlan_act(cx, FORCE_EXEC, false).await?;
            }
            if !cx.btc.auto_report_1ant && self.sta.bt_info_ext & 0x10 == 0 {
                self.bt_auto_report(cx, FORCE_EXEC, true).await?;
            }
        }
        // Check BIT2 first ⇒ check whether BT is under inquiry or page
        // scan.
        self.sta.c2h_bt_inquiry_page = bt_info & BT_INFO_B_INQ_PAGE != 0;
        self.sta.num_of_profile = 0;
        let s = &mut self.sta;
        if bt_info & BT_INFO_B_CONNECTION == 0 {
            s.bt_link_exist = false;
            s.pan_exist = false;
            s.a2dp_exist = false;
            s.hid_exist = false;
            s.sco_exist = false;
            s.bt_hi_pri_link_exist = false;
        } else {
            s.bt_link_exist = true;
            for (bit, exist) in [
                (BT_INFO_B_FTP, &mut s.pan_exist),
                (BT_INFO_B_A2DP, &mut s.a2dp_exist),
                (BT_INFO_B_HID, &mut s.hid_exist),
                (BT_INFO_B_SCO_ESCO, &mut s.sco_exist),
            ] {
                *exist = bt_info & bit != 0;
                if *exist {
                    s.num_of_profile += 1;
                }
            }
            let hp = s.high_priority_tx.wrapping_add(s.high_priority_rx);
            let lp = s.low_priority_tx.wrapping_add(s.low_priority_rx);
            if !s.hid_exist && !s.c2h_bt_inquiry_page && !s.sco_exist && hp >= 160 {
                s.hid_exist = true;
                s.wrong_profile_notification = s.wrong_profile_notification.wrapping_add(1);
                s.num_of_profile += 1;
                bt_info |= 0x28;
            }
            // Add Hi-Pri Tx/Rx counter to avoid false detection.
            if (s.hid_exist || s.sco_exist) && hp >= 160 && !s.c2h_bt_inquiry_page {
                s.bt_hi_pri_link_exist = true;
            }
            if bt_info & BT_INFO_B_ACL_BUSY != 0 && s.num_of_profile == 0 && lp >= 160 {
                s.pan_exist = true;
                s.num_of_profile += 1;
                s.wrong_profile_notification = s.wrong_profile_notification.wrapping_add(1);
                bt_info |= 0x88;
            }
        }
        self.update_bt_link_info(cx);
        // Mask profile bits for status check.
        let bt_info = bt_info & 0x1f;
        self.dm.bt_status = if bt_info & BT_INFO_B_CONNECTION == 0 {
            BtStatus::NonConnectedIdle
        } else if bt_info == BT_INFO_B_CONNECTION {
            // Connection exists but no busy.
            BtStatus::ConnectedIdle
        } else if bt_info & (BT_INFO_B_SCO_ESCO | BT_INFO_B_SCO_BUSY) != 0 {
            BtStatus::ScoBusy
        } else if bt_info & BT_INFO_B_ACL_BUSY != 0 {
            if self.dm.bt_status != BtStatus::AclBusy {
                self.dm.auto_tdma_adjust = false;
            }
            BtStatus::AclBusy
        } else {
            BtStatus::Max
        };
        // BTC_SET_BL_BT_TRAFFIC_BUSY.
        cx.btc.bt_info.bt_busy = self.dm.bt_status.busy();
        self.run_coexist_mechanism(cx).await
    }

    /// `ex_btc8723b1ant_halt_notify`.
    async fn halt_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        cx.btc.stop_coex_dm = true;
        self.set_ant_path(cx, BTC_ANT_PATH_BT, FORCE_EXEC, false, true)
            .await?;
        self.ignore_wlan_act(cx, FORCE_EXEC, true).await?;
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ps_tdma(cx, FORCE_EXEC, false, 0).await?;
        // `stop_coex_dm` is already set, so this media notify returns at
        // its first check, exactly as in Linux.
        super::btc::Algorithm::media_status_notify(self, cx, Media::Disconnect).await?;
        cx.btc.stop_coex_dm = true;
        Ok(())
    }

    /// `ex_btc8723b1ant_pnp_notify`.
    async fn pnp_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, state: Pnp) -> R {
        match state {
            Pnp::Sleep => {
                self.set_ant_path(cx, BTC_ANT_PATH_BT, FORCE_EXEC, false, true)
                    .await?;
                self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                    .await?;
                self.ps_tdma(cx, NORMAL_EXEC, false, 0).await?;
                self.coex_table_with_type(cx, NORMAL_EXEC, 2)?;
                self.sta.under_ips = false;
                self.sta.under_lps = false;
                cx.btc.stop_coex_dm = true;
            }
            Pnp::WakeUp => {
                cx.btc.stop_coex_dm = false;
                self.init_hw_config_inner(cx, false, false).await?;
                self.init_coex_dm_inner(cx).await?;
                self.query_bt_info(cx).await?;
            }
            Pnp::SleepKeepAnt => {}
        }
        Ok(())
    }

    /// `ex_btc8723b1ant_periodical`.
    async fn periodical<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if !cx.btc.auto_report_1ant {
            self.query_bt_info(cx).await?;
            self.monitor_bt_enable_disable(cx).await
        } else {
            self.monitor_bt_ctr(cx).await?;
            self.monitor_wifi_ctr(cx)?;
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
            self.sta.special_pkt_period_cnt = self.sta.special_pkt_period_cnt.wrapping_add(1);
            Ok(())
        }
    }
}
