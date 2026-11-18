// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2012 Realtek Corporation.
//! RTL8821A one-antenna coexistence, Linux 7.3-rc4 halbtc8821a1ant.{c,h},
//! Source C SHA256: 23c8404d08aa96913e722205362a5925fb2ba1d2d0812051365901782fda23d8.
//! Source header SHA256: 0626a9a0b0dbe8f38fa218c6076460695133615aa61d322583328d0245b3b1dd.
//! source version 20130816/0x41. Native integration is separate. Every source
//! static is instance-owned, and fallible effects stop at their first error.
//! Debugfs formatting is omitted; real reads/BT queries in handlers remain.

use super::btc::{
    self, Algorithm, Associate, BtReg, Ctx, Hal, Ips, Lps, Media, Packet, Pnp, PowerSave,
    RssiState, Scan, WifiBw, BTC_ANTENNA_AT_MAIN_PORT, BTC_ANT_PATH_BT, BTC_ANT_PATH_PTA,
    BTC_ANT_PATH_WIFI, WIFI_P2P_GO_CONNECTED,
};
use crate::rtlwifi::prepare::Error;
type R = Result<(), Error>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BtStatus {
    #[default]
    NonConnectedIdle,
    ConnectedIdle,
    InqPage,
    AclBusy,
    ScoBusy,
    AclScoBusy,
    Max,
}
impl BtStatus {
    fn busy(self) -> bool {
        matches!(self, Self::AclBusy | Self::ScoBusy | Self::AclScoBusy)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiStatus {
    NonConnectedIdle,
    NonConnectedAssoAuthScan,
    ConnectedScan,
    ConnectedSpecialPkt,
    ConnectedIdle,
    ConnectedBusy,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum CoexAlgo {
    #[default]
    Undefined,
    Sco,
    Hid,
    A2dp,
    A2dpPanHs,
    PanEdr,
    PanHs,
    PanEdrA2dp,
    PanEdrHid,
    HidA2dpPanEdr,
    HidA2dp,
}
#[derive(Clone, Debug, Default)]
pub struct CoexDm {
    pub cur_ignore_wlan_act: bool,
    pub pre_ignore_wlan_act: bool,
    pub pre_ps_tdma: u8,
    pub cur_ps_tdma: u8,
    pub ps_tdma_para: [u8; 5],
    pub tdma_adj_type: u8,
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
    pub backup_arfr_cnt1: u32,
    pub backup_arfr_cnt2: u32,
    pub backup_retry_limit: u16,
    pub backup_ampdu_max_time: u8,
    pub pre_algorithm: CoexAlgo,
    pub cur_algorithm: CoexAlgo,
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
#[derive(Clone, Debug, Default)]
pub struct CoexSta {
    pub bt_disabled: bool,
    pub bt_link_exist: bool,
    pub sco_exist: bool,
    pub a2dp_exist: bool,
    pub hid_exist: bool,
    pub pan_exist: bool,
    pub under_lps: bool,
    pub under_ips: bool,
    pub special_pkt_period_cnt: u32,
    pub high_priority_tx: u32,
    pub high_priority_rx: u32,
    pub low_priority_tx: u32,
    pub low_priority_rx: u32,
    pub bt_rssi: u8,
    pub bt_tx_rx_mask: bool,
    pub pre_bt_rssi_state: RssiState,
    pub pre_wifi_rssi_state: [RssiState; 4],
    pub c2h_bt_info_req_sent: bool,
    pub bt_info_c2h: [[u8; 10]; 3],
    pub bt_info_c2h_cnt: [u32; 3],
    pub c2h_bt_inquiry_page: bool,
    pub wifi_is_high_pri_task: bool,
    pub bt_retry_cnt: u8,
    pub bt_info_ext: u8,
}
#[derive(Clone, Debug, Default)]
pub struct B8821a1Ant {
    pub dm: CoexDm,
    pub sta: CoexSta,
    dis_ver_info_cnt: u8,
}

pub const COEX_TABLES: [(u32, u32); 8] = [
    (0x55555555, 0x55555555),
    (0x55555555, 0x5a5a5a5a),
    (0x5a5a5a5a, 0x5a5a5a5a),
    (0x5a5a5a5a, 0xaaaaaaaa),
    (0x55555555, 0x5a5a5a5a),
    (0x5a5a5a5a, 0xaaaa5a5a),
    (0x55555555, 0xaaaa5a5a),
    (0xaaaaaaaa, 0xaaaaaaaa),
];
pub const fn ps_tdma_bytes(on: bool, ty: u8) -> [u8; 5] {
    if !on {
        return match ty {
            8 => [8, 0, 0, 0, 0],
            10 => [0, 0, 0, 8, 0],
            _ => [0; 5],
        };
    }
    match ty {
        1 => [0x51, 0x3a, 3, 0x10, 0x50],
        2 => [0x51, 0x2b, 3, 0x10, 0x50],
        3 => [0x51, 0x1d, 0x1d, 0, 0x10],
        4 => [0x93, 0x15, 3, 0x14, 0],
        5 => [0x61, 0x15, 3, 0x11, 0x10],
        6 => [0x61, 0x20, 3, 0x11, 0x13],
        7 => [0x13, 0xc, 5, 0, 0],
        8 => [0x93, 0x25, 3, 0x10, 0],
        9 => [0x51, 0x21, 3, 0x10, 0x50],
        10 => [0x13, 0xa, 0xa, 0, 0x40],
        11 => [0x51, 0x15, 3, 0x10, 0x50],
        12 => [0x51, 0xa, 0xa, 0, 0x50],
        13 => [0x51, 0x12, 0x12, 0, 0x50],
        14 => [0x51, 0x1e, 3, 0x10, 0x14],
        15 => [0x13, 0xa, 3, 8, 0],
        16 => [0x93, 0x15, 3, 0x10, 0],
        18 => [0x93, 0x25, 3, 0x10, 0],
        20 => [0x61, 0x35, 3, 0x11, 0x10],
        21 => [0x61, 0x25, 3, 0x11, 0x11],
        22 => [0x61, 0x25, 3, 0x11, 0x10],
        23 => [0xe3, 0x25, 3, 0x31, 0x18],
        24 => [0xe3, 0x15, 3, 0x31, 0x18],
        25 | 26 => [0xe3, 0xa, 3, 0x31, 0x18],
        27 => [0xe3, 0x25, 3, 0x31, 0x98],
        28 => [0x69, 0x25, 3, 0x31, 0],
        29 => [0xab, 0x1a, 0x1a, 1, 0x10],
        30 => [0x51, 0x30, 3, 0x10, 0x10],
        31 => [0xd3, 0x1a, 0x1a, 0, 0x58],
        32 => [0x61, 0x35, 3, 0x11, 0x11],
        33 => [0xa3, 0x25, 3, 0x30, 0x90],
        34 => [0x53, 0x1a, 0x1a, 0, 0x10],
        35 => [0x63, 0x1a, 0x1a, 0, 0x10],
        36 => [0xd3, 0x12, 3, 0x14, 0x50],
        40 => [0x23, 0x18, 0, 0x10, 0x24],
        41 => [0x51, 0x15, 3, 0x11, 0x11],
        42 => [0x51, 0x20, 3, 0x11, 0x11],
        43 => [0x51, 0x30, 3, 0x10, 0x11],
        _ => [0x51, 0x1a, 0x1a, 0, 0x50],
    }
}
pub const fn ap_tdma(mut b: [u8; 5], ap: bool) -> [u8; 5] {
    if ap && b[0] & 0x10 != 0 && b[0] & 0x20 == 0 {
        b[0] = (b[0] & !0x10) | 0x20;
        b[4] = (b[4] | 0x20) & !0x40;
    }
    b
}
pub fn action_algorithm(l: &btc::BtLinkInfo, hs: bool) -> CoexAlgo {
    use CoexAlgo::*;
    if !l.bt_link_exist {
        return Undefined;
    }
    let n = [l.sco_exist, l.hid_exist, l.pan_exist, l.a2dp_exist]
        .iter()
        .filter(|v| **v)
        .count();
    match n {
        1 => {
            if l.sco_exist {
                Sco
            } else if l.hid_exist {
                Hid
            } else if l.a2dp_exist {
                A2dp
            } else if hs {
                PanHs
            } else {
                PanEdr
            }
        }
        2 => {
            if l.sco_exist {
                if l.hid_exist {
                    Hid
                } else if l.a2dp_exist || hs {
                    Sco
                } else {
                    PanEdrHid
                }
            } else if l.hid_exist && l.a2dp_exist || l.hid_exist && l.pan_exist && hs {
                HidA2dp
            } else if l.hid_exist && l.pan_exist {
                PanEdrHid
            } else if hs {
                A2dpPanHs
            } else {
                PanEdrA2dp
            }
        }
        3 => {
            if l.sco_exist {
                if l.hid_exist && l.a2dp_exist {
                    Hid
                } else if l.hid_exist {
                    if hs {
                        HidA2dp
                    } else {
                        PanEdrHid
                    }
                } else if hs {
                    Sco
                } else {
                    PanEdrHid
                }
            } else if hs {
                HidA2dp
            } else {
                HidA2dpPanEdr
            }
        }
        4 => {
            if hs {
                Undefined
            } else {
                PanEdrHid
            }
        }
        _ => Undefined,
    }
}

impl B8821a1Ant {
    pub fn new() -> Self {
        Self::default()
    }
}

impl B8821a1Ant {
    fn stopped<H: Hal>(&self, cx: &Ctx<'_, H>) -> bool {
        cx.btc.manual_control || cx.btc.stop_coex_dm
    }
    async fn notify_multiport<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<bool, Error> {
        if cx.btc.wifi.link_status() >> 16 < 2 {
            return Ok(false);
        }
        self.limited_tx(cx, false, 0, 0, 0, 0)?;
        self.limited_rx(cx, false, false, false, 5);
        self.multiport_action(cx).await?;
        Ok(true)
    }
    async fn notify_inquiry_hs<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<bool, Error> {
        if self.sta.c2h_bt_inquiry_page {
            self.inquiry(cx).await?;
            Ok(true)
        } else if cx.hs_operation() {
            self.hs(cx).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
impl Algorithm for B8821a1Ant {
    async fn power_on_setting<H: Hal>(&mut self, _: &mut Ctx<'_, H>) -> R {
        // exhalbtc_power_on_setting has no8821A branch.
        Ok(())
    }
    async fn init_hw_config<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, wifi_only: bool) -> R {
        self.init_hw(cx, true, wifi_only).await?;
        cx.btc.auto_report_1ant = true;
        Ok(())
    }
    async fn init_coex_dm<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        cx.btc.stop_coex_dm = false;
        self.init_dm(cx).await?;
        self.query_bt_info(cx).await
    }
    async fn ips_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Ips) -> R {
        if self.stopped(cx) {
            return Ok(());
        }
        if cx.btc.wifi.under_5g {
            return self.under_5g(cx).await;
        }
        match ty {
            Ips::Enter => {
                self.sta.under_ips = true;
                self.set_ant_path(cx, BTC_ANT_PATH_BT, false, true).await?;
                self.ps_tdma(cx, false, false, 0).await?;
                self.coex_table_with_type(cx, false, 0)
            }
            Ips::Leave => {
                self.sta.under_ips = false;
                self.init_hw(cx, false, false).await?;
                self.init_dm(cx).await?;
                self.query_bt_info(cx).await
            }
        }
    }
    async fn lps_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Lps) -> R {
        if !self.stopped(cx) {
            self.sta.under_lps = ty == Lps::Enable;
        }
        Ok(())
    }
    async fn scan_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Scan) -> R {
        if self.stopped(cx) {
            return Ok(());
        }
        if cx.btc.wifi.under_5g {
            return self.under_5g(cx).await;
        }
        if ty == Scan::Start {
            self.sta.wifi_is_high_pri_task = true;
            self.ps_tdma(cx, true, false, 8).await?;
        } else {
            self.sta.wifi_is_high_pri_task = false;
        }
        if self.sta.bt_disabled {
            return Ok(());
        }
        self.query_bt_info(cx).await?;
        if self.notify_multiport(cx).await? || self.notify_inquiry_hs(cx).await? {
            return Ok(());
        }
        match ty {
            Scan::Start => self.scan_action(cx).await,
            Scan::Finish => {
                if cx.btc.wifi.connected() {
                    self.connected(cx).await
                } else {
                    self.not_connected(cx).await
                }
            }
            _ => Ok(()),
        }
    }
    async fn connect_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Associate) -> R {
        if self.stopped(cx) || self.sta.bt_disabled {
            return Ok(());
        }
        if cx.btc.wifi.under_5g {
            return self.under_5g(cx).await;
        }
        self.sta.wifi_is_high_pri_task = ty == Associate::Start;
        self.dm.arp_cnt = 0;
        if self.notify_multiport(cx).await? || self.notify_inquiry_hs(cx).await? {
            return Ok(());
        }
        match ty {
            Associate::Start => self.scan_action(cx).await,
            Associate::Finish => {
                if cx.btc.wifi.connected() {
                    self.connected(cx).await
                } else {
                    self.not_connected(cx).await
                }
            }
            _ => Ok(()),
        }
    }
    async fn media_status_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Media) -> R {
        if self.stopped(cx) || self.sta.bt_disabled {
            return Ok(());
        }
        if cx.btc.wifi.under_5g {
            return self.under_5g(cx).await;
        }
        if ty == Media::Disconnect {
            self.dm.arp_cnt = 0;
        }
        let channel = cx.btc.wifi.central_chnl();
        let value = if ty == Media::Connect && channel <= 14 {
            [
                0,
                channel,
                if cx.btc.wifi.bw() == WifiBw::Ht40 {
                    0x30
                } else {
                    0x20
                },
            ]
        } else {
            [0; 3]
        };
        self.dm.wifi_chnl_info = value;
        cx.fill_h2c(0x66, &value).await
    }
    async fn special_packet_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Packet) -> R {
        if self.stopped(cx) || self.sta.bt_disabled {
            return Ok(());
        }
        if cx.btc.wifi.under_5g {
            return self.under_5g(cx).await;
        }
        let special = matches!(ty, Packet::Dhcp | Packet::Eapol | Packet::Arp);
        self.sta.wifi_is_high_pri_task = special;
        self.sta.special_pkt_period_cnt = 0;
        if self.notify_multiport(cx).await? || self.notify_inquiry_hs(cx).await? {
            return Ok(());
        }
        if special {
            if ty == Packet::Arp {
                self.dm.arp_cnt = self.dm.arp_cnt.wrapping_add(1);
                if self.dm.arp_cnt >= 10 {
                    return Ok(());
                }
            }
            self.connected_special(cx).await?;
        }
        Ok(())
    }
    async fn bt_info_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, buf: &[u8]) -> R {
        if !(2..=10).contains(&buf.len()) {
            return Err(Error::Packet);
        }
        let source = if buf[0] & 0xf < 3 {
            (buf[0] & 0xf) as usize
        } else {
            0
        };
        if source != 0 && buf.len() < 5 {
            return Err(Error::Packet);
        }
        self.sta.c2h_bt_info_req_sent = false;
        let under5 = cx.btc.wifi.under_5g;
        self.sta.bt_info_c2h_cnt[source] = self.sta.bt_info_c2h_cnt[source].wrapping_add(1);
        self.sta.bt_info_c2h[source][..buf.len()].copy_from_slice(buf);
        let mut info = buf[1];
        if source != 0 {
            self.sta.bt_retry_cnt = buf[2] & 0xf;
            self.sta.bt_rssi = buf[3].wrapping_mul(2).wrapping_add(10);
            self.sta.bt_info_ext = buf[4];
            self.sta.bt_tx_rx_mask = buf[2] & 0x40 != 0;
            cx.btc.bt_info.bt_tx_rx_mask = self.sta.bt_tx_rx_mask;
            if !self.sta.bt_tx_rx_mask {
                cx.set_bt_reg(BtReg::Rf, 0x3c, 0x15).await?;
            }
            if self.sta.bt_info_ext & 2 != 0 {
                self.media_status_notify(
                    cx,
                    if cx.btc.wifi.connected() {
                        Media::Connect
                    } else {
                        Media::Disconnect
                    },
                )
                .await?;
            }
            if self.sta.bt_info_ext & 8 != 0 && !under5 && !self.stopped(cx) {
                self.ignore_wlan_act(cx, true, false).await?;
            }
        }
        self.sta.c2h_bt_inquiry_page = info & 4 != 0;
        self.sta.bt_link_exist = info & 1 != 0;
        self.sta.pan_exist = self.sta.bt_link_exist && info & 0x80 != 0;
        self.sta.a2dp_exist = self.sta.bt_link_exist && info & 0x40 != 0;
        self.sta.hid_exist = self.sta.bt_link_exist && info & 0x20 != 0;
        self.sta.sco_exist = self.sta.bt_link_exist && info & 2 != 0;
        self.update_bt_link_info(cx);
        info &= 0x1f;
        let status = if info & 1 == 0 {
            BtStatus::NonConnectedIdle
        } else if info == 1 {
            BtStatus::ConnectedIdle
        } else if info & (2 | 0x10) != 0 {
            BtStatus::ScoBusy
        } else if info & 8 != 0 {
            BtStatus::AclBusy
        } else {
            BtStatus::Max
        };
        if status == BtStatus::AclBusy && self.dm.bt_status != status {
            self.dm.auto_tdma_adjust = false;
        }
        self.dm.bt_status = status;
        cx.btc.bt_info.bt_busy = status.busy();
        self.run(cx).await
    }
    async fn halt_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if cx.btc.wifi.under_5g {
            return self.under_5g(cx).await;
        }
        cx.btc.stop_coex_dm = true;
        self.set_ant_path(cx, BTC_ANT_PATH_BT, false, true).await?;
        self.ignore_wlan_act(cx, true, true).await?;
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ps_tdma(cx, true, false, 0).await?;
        // Source media_status observes stop_coex_dm and therefore emits nothing.
        self.media_status_notify(cx, Media::Disconnect).await
    }
    async fn pnp_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, state: Pnp) -> R {
        if cx.btc.wifi.under_5g {
            return self.under_5g(cx).await;
        }
        match state {
            Pnp::Sleep => {
                self.sta.under_ips = false;
                self.sta.under_lps = false;
                cx.btc.stop_coex_dm = true;
                self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                    .await?;
                self.ps_tdma(cx, false, false, 0).await?;
                self.coex_table_with_type(cx, false, 2)?;
                self.set_ant_path(cx, BTC_ANT_PATH_BT, false, true).await
            }
            Pnp::WakeUp => {
                cx.btc.stop_coex_dm = false;
                self.init_hw(cx, false, false).await?;
                self.init_dm(cx).await?;
                self.query_bt_info(cx).await
            }
            Pnp::SleepKeepAnt => Ok(()), // no source branch for this notification.
        }
    }
    async fn periodical<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if self.dis_ver_info_cnt <= 5 {
            self.dis_ver_info_cnt += 1;
            // This is a real BT MP query even though C only prints its result.
            let _ = cx.bt_patch_version().await?;
        }
        if !cx.btc.auto_report_1ant {
            self.query_bt_info(cx).await?;
            self.monitor_bt_ctr(cx)
        } else {
            self.sta.special_pkt_period_cnt = self.sta.special_pkt_period_cnt.wrapping_add(1);
            Ok(())
        }
    }
}

impl B8821a1Ant {
    fn coex_table_with_type<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, force: bool, ty: u8) -> R {
        if let Some(&(a, b)) = COEX_TABLES.get(ty as usize) {
            self.coex_table(cx, force, a, b, 0xffffff, 3)?;
        }
        Ok(())
    }
    fn monitor_bt_ctr<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let high = cx.read_4byte(0x770)?;
        let low = cx.read_4byte(0x774)?;
        self.sta.high_priority_tx = high & 0xffff;
        self.sta.high_priority_rx = high >> 16;
        self.sta.low_priority_tx = low & 0xffff;
        self.sta.low_priority_rx = low >> 16;
        cx.write_1byte(0x76e, 0xc)
    }
    pub async fn set_ant_path<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        path: u8,
        init: bool,
        wifi_off: bool,
    ) -> R {
        let main = cx.btc.board_info.btdm_ant_pos == BTC_ANTENNA_AT_MAIN_PORT;
        if init {
            let value = cx.read_4byte(0x4c)?;
            cx.write_4byte(0x4c, (value & !(1 << 23)) | (1 << 24))?;
            cx.write_1byte_bitmask(0x975, 3, 3)?;
            cx.write_1byte(0xcb4, 0x77)?;
            cx.fill_h2c(0x65, &[u8::from(main), 1]).await?;
        } else if wifi_off {
            let value = cx.read_4byte(0x4c)?;
            cx.write_4byte(0x4c, value & !((1 << 23) | (1 << 24)))?;
            cx.write_1byte_bitmask(0x765, 0x18, 3)?;
        } else {
            cx.write_1byte_bitmask(0x765, 0x18, 0)?;
        }
        let (control, selector) = match path {
            BTC_ANT_PATH_WIFI => (0x77, if main { 1 } else { 2 }),
            BTC_ANT_PATH_BT => (0x77, if main { 2 } else { 1 }),
            _ => (0x66, if main { 1 } else { 2 }),
        };
        cx.write_1byte(0xcb4, control)?;
        cx.write_1byte_bitmask(0xcb7, 0x30, selector)
    }
    pub async fn ps_tdma<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        force: bool,
        on: bool,
        ty: u8,
    ) -> R {
        self.dm.cur_ps_tdma_on = on;
        self.dm.cur_ps_tdma = ty;
        if !force && self.dm.pre_ps_tdma_on == on && self.dm.pre_ps_tdma == ty {
            return Ok(());
        }
        self.set_fw_ps_tdma(cx, ps_tdma_bytes(on, ty)).await?;
        if !on {
            let path = match ty {
                8 => BTC_ANT_PATH_PTA,
                9 => BTC_ANT_PATH_WIFI,
                _ => BTC_ANT_PATH_BT,
            };
            self.set_ant_path(cx, path, false, false).await?;
        }
        // The C source resets this to zero after its per-case assignments.
        cx.btc.bt_info.rssi_adjust_for_1ant_coex_type = 0;
        self.dm.pre_ps_tdma_on = on;
        self.dm.pre_ps_tdma = ty;
        Ok(())
    }
    async fn sw_mechanism<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, low: bool) -> R {
        self.low_penalty_ra(cx, false, low).await
    }
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
            }
            PowerSave::LpsOn => {
                if cx.lps_mode() == 0 {
                    self.ps_tdma(cx, false, false, 0).await?;
                }
                self.lps_rpwm(cx, false, lps, rpwm);
                cx.disable_low_power(true);
                cx.enter_lps().await?;
            }
            PowerSave::LpsOff => {
                if cx.lps_mode() != 0 {
                    self.ps_tdma(cx, false, false, 0).await?;
                }
                cx.leave_lps().await?;
            }
        }
        Ok(())
    }
    async fn under_5g<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.ignore_wlan_act(cx, false, true).await?;
        self.ps_tdma(cx, false, false, 10).await?;
        self.coex_table_with_type(cx, false, 0)?;
        self.limited_tx(cx, false, 0, 0, 0, 0)?;
        self.limited_rx(cx, false, false, false, 5);
        Ok(())
    }
    async fn tdma_table<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        on: bool,
        tdma: u8,
        table: u8,
    ) -> R {
        self.ps_tdma(cx, false, on, tdma).await?;
        self.coex_table_with_type(cx, false, table)
    }
    async fn sco_hid<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.tdma_table(cx, true, 5, 1).await
    }
    async fn acl_busy<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, status: WifiStatus) -> R {
        self.sta.pre_bt_rssi_state = rssi_state(
            self.sta.pre_bt_rssi_state,
            i32::from(self.sta.bt_rssi),
            2,
            28,
            0,
        );
        let l = cx.btc.bt_link_info;
        let (tdma, table) = if l.hid_only {
            (5, 1)
        } else if l.a2dp_only {
            if status == WifiStatus::ConnectedIdle {
                (32, 1)
            } else {
                (14, 1)
            }
        } else if l.hid_exist && l.a2dp_exist {
            (14, 1)
        } else if l.pan_only || l.hid_exist && l.pan_exist {
            (3, 6)
        } else if l.a2dp_exist && l.pan_exist {
            (43, 1)
        } else {
            (11, 1)
        };
        // Source's sole StayHigh branch leaves this flag as-is. Both A2DP
        // branches still select14/1; do not invent adaptive duration logic.
        if !(l.a2dp_only
            && status != WifiStatus::ConnectedIdle
            && self.sta.pre_bt_rssi_state == RssiState::StayHigh)
        {
            self.dm.auto_tdma_adjust = false;
        }
        self.tdma_table(cx, true, tdma, table).await
    }
    async fn multiport_action<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        if self.dm.bt_status == BtStatus::AclBusy {
            // C's later a2dp&&pan branch is shadowed by this first a2dp test.
            if cx.btc.bt_link_info.a2dp_exist {
                self.tdma_table(cx, true, 14, 1).await
            } else {
                self.tdma_table(cx, true, 20, 4).await
            }
        } else if matches!(self.dm.bt_status, BtStatus::ScoBusy | BtStatus::AclScoBusy) {
            self.sco_hid(cx).await
        } else {
            self.tdma_table(cx, false, 8, 2).await
        }
    }
    async fn asso_auth<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        let l = cx.btc.bt_link_info;
        if l.sco_exist || l.hid_exist {
            self.tdma_table(cx, true, 14, 1).await
        } else if l.a2dp_exist || l.pan_exist {
            self.tdma_table(cx, true, 20, 4).await
        } else {
            self.tdma_table(cx, false, 8, 2).await
        }
    }
    async fn inquiry<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let l = cx.btc.bt_link_info;
        cx.btc.bt_info.bt_busy = false;
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        if !cx.btc.wifi.connected() && !self.sta.wifi_is_high_pri_task {
            self.tdma_table(cx, false, 8, 0).await
        } else if l.sco_exist || l.a2dp_exist || l.hid_only {
            self.tdma_table(cx, true, 32, 4).await
        } else if l.a2dp_exist && l.hid_exist {
            self.tdma_table(cx, true, 14, 1).await
        } else if l.pan_exist || cx.btc.wifi.busy {
            self.tdma_table(cx, true, 20, 4).await
        } else {
            self.tdma_table(cx, false, 8, 7).await
        }
    }
    async fn hs<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.ps_tdma(cx, false, true, 5).await?;
        self.coex_table_with_type(cx, true, 2)
    }
    async fn not_connected<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        self.tdma_table(cx, false, 8, 0).await
    }
    async fn scan_action<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        if self.dm.bt_status == BtStatus::AclBusy {
            if cx.btc.bt_link_info.a2dp_exist {
                self.tdma_table(cx, true, 14, 1).await
            } else {
                self.tdma_table(cx, true, 20, 4).await
            }
        } else if matches!(self.dm.bt_status, BtStatus::ScoBusy | BtStatus::AclScoBusy) {
            self.sco_hid(cx).await
        } else {
            self.tdma_table(cx, false, 8, 2).await
        }
    }
    async fn connected_special<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
            .await?;
        let l = cx.btc.bt_link_info;
        // These are two independent source ifs: preserve the intermediate
        //32/4 effect even where the second branch subsequently overrides it.
        if l.sco_exist || l.hid_exist || l.a2dp_exist {
            self.tdma_table(cx, true, 32, 4).await?;
        }
        if l.hid_exist && l.a2dp_exist {
            self.tdma_table(cx, true, 14, 1).await
        } else if l.pan_exist {
            self.tdma_table(cx, true, 20, 4).await
        } else {
            self.tdma_table(cx, false, 8, 2).await
        }
    }
    async fn connected<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        let w = cx.btc.wifi;
        if w.in_4way {
            return self.connected_special(cx).await;
        }
        if w.scanning {
            return self.scan_action(cx).await;
        }
        if w.linking {
            return self.connected_special(cx).await;
        }
        if self.dm.bt_status == BtStatus::AclBusy
            && !w.ap_mode
            && !cx.btc.bt_link_info.hid_only
            && (w.busy || !cx.btc.bt_link_info.a2dp_only)
        {
            self.power_save_state(cx, PowerSave::LpsOn, 0x50, 4).await?;
        } else {
            self.power_save_state(cx, PowerSave::WifiNative, 0, 0)
                .await?;
        }
        if self.dm.bt_status == BtStatus::AclBusy {
            self.acl_busy(
                cx,
                if w.busy {
                    WifiStatus::ConnectedBusy
                } else {
                    WifiStatus::ConnectedIdle
                },
            )
            .await
        } else if matches!(self.dm.bt_status, BtStatus::ScoBusy | BtStatus::AclScoBusy) {
            self.sco_hid(cx).await
        } else {
            self.tdma_table(cx, false, 8, 2).await
        }
    }
    async fn run_sw<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.dm.cur_algorithm = action_algorithm(&cx.btc.bt_link_info, cx.hs_operation());
        if !cx.btc.wifi.connected()
            || matches!(
                self.dm.bt_status,
                BtStatus::NonConnectedIdle | BtStatus::ConnectedIdle
            )
        {
            return self.sw_mechanism(cx, false).await;
        }
        match self.dm.cur_algorithm {
            CoexAlgo::Sco
            | CoexAlgo::Hid
            | CoexAlgo::PanEdrHid
            | CoexAlgo::HidA2dpPanEdr
            | CoexAlgo::HidA2dp => self.sw_mechanism(cx, true).await?,
            CoexAlgo::Undefined => {}
            _ => self.sw_mechanism(cx, false).await?,
        }
        self.dm.pre_algorithm = self.dm.cur_algorithm;
        Ok(())
    }
    pub async fn run<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        if cx.btc.manual_control || cx.btc.stop_coex_dm || self.sta.under_ips {
            return Ok(());
        }
        if cx.btc.wifi.under_5g {
            return self.under_5g(cx).await;
        }
        cx.btc.bt_info.increase_scan_dev_num = self.dm.bt_status.busy();
        let connected = cx.btc.wifi.connected();
        let l = cx.btc.bt_link_info;
        let links = cx.btc.wifi.link_status();
        if links >> 16 >= 2 || links & WIFI_P2P_GO_CONNECTED != 0 {
            self.limited_tx(cx, false, 0, 0, 0, 0)?;
            self.limited_rx(cx, false, false, false, 5);
            return self.multiport_action(cx).await;
        }
        if (l.sco_exist || l.hid_exist) && connected {
            self.sta.pre_wifi_rssi_state[1] =
                rssi_state(self.sta.pre_wifi_rssi_state[1], cx.wifi_rssi(), 2, 30, 0);
            self.limited_tx(cx, false, 1, 1, 0, 1)?;
        } else {
            self.limited_tx(cx, false, 0, 0, 0, 0)?;
        }
        let (control, size) = if l.sco_exist {
            (true, 3)
        } else if l.hid_exist {
            (true, 5)
        } else if l.a2dp_exist || l.pan_exist {
            (true, 8)
        } else {
            (false, 5)
        };
        self.limited_rx(cx, false, false, control, size);
        self.run_sw(cx).await?;
        if self.sta.c2h_bt_inquiry_page {
            return self.inquiry(cx).await;
        }
        if cx.hs_operation() {
            return self.hs(cx).await;
        }
        if connected {
            self.connected(cx).await
        } else if cx.btc.wifi.scanning {
            self.scan_action(cx).await
        } else if cx.btc.wifi.linking {
            self.asso_auth(cx).await
        } else {
            self.not_connected(cx).await
        }
    }
    async fn init_dm<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.sw_mechanism(cx, false).await?;
        self.coex_table_with_type(cx, true, 0)
    }
    async fn init_hw<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, backup: bool, wifi_only: bool) -> R {
        if wifi_only {
            return Ok(());
        }
        if backup {
            self.dm.backup_arfr_cnt1 = cx.read_4byte(0x430)?;
            self.dm.backup_arfr_cnt2 = cx.read_4byte(0x434)?;
            self.dm.backup_retry_limit = cx.read_2byte(0x42a)?;
            self.dm.backup_ampdu_max_time = cx.read_1byte(0x456)?;
        }
        let before = cx.read_1byte(0x790)?;
        cx.write_1byte(0x790, (before & 0xc0) | 5)?;
        self.set_ant_path(
            cx,
            if cx.btc.wifi.under_5g {
                BTC_ANT_PATH_BT
            } else {
                BTC_ANT_PATH_PTA
            },
            true,
            false,
        )
        .await?;
        self.coex_table_with_type(cx, true, 0)?;
        cx.write_1byte(0x76e, 0xc)?;
        cx.write_1byte(0x778, 3)?;
        cx.write_1byte_bitmask(0x40, 0x20, 1)
    }
}

const H2C_BT_INFO: u8 = 0x61;
const H2C_LOW_PENALTY_RA: u8 = 0x69;
const H2C_IGNORE_WLAN_ACT: u8 = 0x63;
const H2C_TDMA: u8 = 0x60;
impl B8821a1Ant {
    /// `btc8821a1ant_updatera_mask`.
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

    /// `btc8821a1ant_retry_limit`.
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

    /// `btc8821a1ant_ampdu_maxtime`.
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

    /// `btc8821a1ant_limited_tx`.
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

    /// `btc8821a1ant_limited_rx` (`force_exec` is unused in Linux).
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

    /// `btc8821a1ant_query_bt_info`.
    async fn query_bt_info<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> R {
        self.sta.c2h_bt_info_req_sent = true;
        cx.fill_h2c(H2C_BT_INFO, &[1]).await
    }

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

    /// `btc8821a1ant_coex_table` → `set_coex_table`.
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

    /// `btc8821a1ant_ignore_wlan_act` → `set_fw_ignore_wlan_act`.
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

    /// `btc8821a1ant_set_fw_ps_tdma`.
    async fn set_fw_ps_tdma<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, bytes: [u8; 5]) -> R {
        let b = ap_tdma(bytes, cx.btc.wifi.ap_mode);
        self.dm.ps_tdma_para = b;
        cx.fill_h2c(H2C_TDMA, &b).await
    }

    /// `btc8821a1ant_lps_rpwm` → `set_lps_rpwm`.
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
}

/// Source two/three-level RSSI hysteresis, tolerance 2.
pub fn rssi_state(pre: RssiState, rssi: i32, level_num: u8, thresh: u8, thresh1: u8) -> RssiState {
    let t = i32::from(thresh);
    let t1 = i32::from(thresh1);
    let low = matches!(pre, RssiState::Low | RssiState::StayLow);
    let medium = matches!(pre, RssiState::Medium | RssiState::StayMedium);
    match level_num {
        2 => {
            if low {
                if rssi >= t + 2 {
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
                if rssi >= t + 2 {
                    RssiState::Medium
                } else {
                    RssiState::StayLow
                }
            } else if medium {
                if rssi >= t1 + 2 {
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "b8821a1ant_tests.rs"]
mod tests;
