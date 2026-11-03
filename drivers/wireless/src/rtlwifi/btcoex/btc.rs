// SPDX-License-Identifier: GPL-2.0-or-later
//! rtlwifi BT-coexistence glue: `btcoexist/halbtcoutsrc.{c,h}` and
//! `btcoexist/rtl_btc.c` (Linux 7.3-rc4).
//!
//! [`BtCoexist`] is `struct btc_coexist` without its function pointers:
//! board info (`exhalbtc_bind_bt_coex_withadapter`), `bt_info`,
//! `stack_info`, `bt_link_info`, the statistics, `pwr_mode_val` and the
//! manual-control / stop flags. The function pointers become the [`Hal`]
//! trait (`halbtc_read_*` / `halbtc_write_*` / `halbtc_set_rfreg` /
//! `fill_h2c_cmd`, the C2H MP-response wait, `rtl_lps_{enter,leave}`,
//! `rtl_rx_ampdu_apply`) and [`Ctx`] (one borrow of the state plus the
//! HAL) carries `halbtc_bitmask_write_1byte`,
//! `halbtc_write_local_reg_1byte`, `halbtc_send_bt_mp_operation`,
//! `halbtc_set_bt_reg`, the `halbtc_get` queries over [`WifiInfo`] and the
//! `halbtc_set` actions. The per-chip algorithms (`halbtc8723b1ant.c`,
//! `halbtc8723b2ant.c`) implement [`Algorithm`]; the `exhalbtc_*` notify
//! entry points (and the `rtl_btc_*` wrappers that add behaviour) are
//! [`Ctx`] methods dispatching to it.
//!
//! [`WifiInfo`] is the driver state `halbtc_get` reads live in Linux
//! (`mac80211.opmode/link_state/act_scanning/mode`, `link_info`,
//! `phy.current_channel/current_chan_bw`, `dm.undec_sm_pwdb`,
//! `btc_info.in_4way/ap_num`, the firmware version); the owner refreshes it
//! before each notify.
//!
//! Differences from Linux:
//! - Register / H2C / RF access errors propagate (`?`) where Linux
//!   ignores them; a failed access ends the notify.
//! - `bt_mp_comp`: the C2H `BT_MP` body arrives through the RX ring, so the
//!   HAL returns each body that arrives within the wait and the glue runs
//!   `rtl_btc_btmpinfo_notify` on it; Linux's `complete()` corresponds to a
//!   body that notify accepts (`extid == 1`, `len >= 4`). At most
//!   [`MP_WAIT_ROUNDS`] bodies are taken per operation.
//! - `halbtc_aggregation_check`'s `static pre_time` is per-instance and
//!   unset until the first check (which therefore always runs).
//! - `halbtc_display_*` / `btc_disp_dbg_msg` (debugfs) are not carried.

#![allow(dead_code)]

use crate::rtlwifi::prepare::Error;

/// `NORMAL_EXEC` / `FORCE_EXEC`.
pub const NORMAL_EXEC: bool = false;
pub const FORCE_EXEC: bool = true;

/// `BTC_RF_A` / `BTC_RF_B` (`RF90_PATH_*`).
pub const BTC_RF_A: u8 = 0;
pub const BTC_RF_B: u8 = 1;

/// Single-antenna paths (`BTC_ANT_PATH_*`).
pub const BTC_ANT_PATH_WIFI: u8 = 0;
pub const BTC_ANT_PATH_BT: u8 = 1;
pub const BTC_ANT_PATH_PTA: u8 = 2;
pub const BTC_ANT_PATH_WIFI5G: u8 = 3;
pub const BTC_ANT_PATH_AUTO: u8 = 4;
/// Dual-antenna positions (`BTC_ANT_WIFI_AT_*`).
pub const BTC_ANT_WIFI_AT_MAIN: u8 = 0;
pub const BTC_ANT_WIFI_AT_AUX: u8 = 1;

/// `BTC_ANTENNA_AT_MAIN_PORT` / `BTC_ANTENNA_AT_AUX_PORT`.
pub const BTC_ANTENNA_AT_MAIN_PORT: u8 = 1;
pub const BTC_ANTENNA_AT_AUX_PORT: u8 = 2;

/// `halbtc_get_wifi_link_status` port bits.
pub const WIFI_STA_CONNECTED: u32 = 1 << 0;
pub const WIFI_AP_CONNECTED: u32 = 1 << 1;
pub const WIFI_HS_CONNECTED: u32 = 1 << 2;
pub const WIFI_P2P_GO_CONNECTED: u32 = 1 << 3;
pub const WIFI_P2P_GC_CONNECTED: u32 = 1 << 4;

/// `MASKDWORD`.
pub const MASKDWORD: u32 = 0xffff_ffff;

/// `fill_h2c_cmd` element id of a BT MP operation.
pub const H2C_BT_MP_OPER: u8 = 0x67;
/// `halbtc_set_bt_reg` / `halbtc_get_bt_patch_version` wait (ms).
pub const BT_MP_WAIT_MS: u32 = 200;
/// Bodies taken per MP operation (see the module documentation).
pub const MP_WAIT_ROUNDS: u32 = 8;

/// `enum btc_chip_interface`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChipInterface {
    Unknown = 0,
    Pci = 1,
    Usb = 2,
    Sdio = 3,
}

/// `enum btc_chip_type` (`exhalbtc_set_chip_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChipType {
    Undef = 0,
    CsrBc4 = 1,
    CsrBc8 = 2,
    Rtl8723a = 3,
    Rtl8821 = 4,
    Rtl8723b = 5,
}

/// `enum btc_rssi_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RssiState {
    High = 0,
    Medium = 1,
    Low = 2,
    StayHigh = 3,
    StayMedium = 4,
    StayLow = 5,
}

impl RssiState {
    /// `BTC_RSSI_HIGH`.
    pub const fn high(self) -> bool {
        matches!(self, Self::High | Self::StayHigh)
    }
    /// `BTC_RSSI_MEDIUM`.
    pub const fn medium(self) -> bool {
        matches!(self, Self::Medium | Self::StayMedium)
    }
    /// `BTC_RSSI_LOW`.
    pub const fn low(self) -> bool {
        matches!(self, Self::Low | Self::StayLow)
    }
}

/// `enum btc_wifi_bw_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiBw {
    Legacy = 0,
    Ht20 = 1,
    Ht40 = 2,
    Ht80 = 3,
}

/// `enum btc_wifi_traffic_dir`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficDir {
    Tx = 0,
    Rx = 1,
}

/// `enum btc_wifi_pnp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pnp {
    WakeUp = 0,
    Sleep = 1,
    SleepKeepAnt = 2,
}

/// `enum btc_notify_type_ips`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ips {
    Leave = 0,
    Enter = 1,
}

/// `enum btc_notify_type_lps`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lps {
    Disable = 0,
    Enable = 1,
}

/// `enum btc_notify_type_scan` (`exhalbtc_scan_notify` only produces
/// `START` / `FINISH`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scan {
    Finish = 0,
    Start = 1,
    Start2G = 2,
}

/// `enum btc_notify_type_associate`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Associate {
    Finish = 0,
    Start = 1,
    Finish5G = 2,
    Start5G = 3,
}

/// `enum btc_notify_type_media_status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Media {
    Disconnect = 0,
    Connect = 1,
}

/// `enum btc_notify_type_special_packet`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Packet {
    Unknown = 0,
    Dhcp = 1,
    Arp = 2,
    Eapol = 3,
}

/// `enum btc_bt_reg_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtReg {
    Rf = 0,
    Modem = 1,
    Bluewize = 2,
    Vendor = 3,
    Le = 4,
}

/// `enum btc_mp_h2c_op_code`.
pub const BT_OP_GET_BT_VERSION: u8 = 0;
pub const BT_OP_WRITE_REG_ADDR: u8 = 12;
pub const BT_OP_WRITE_REG_VALUE: u8 = 13;
pub const BT_OP_READ_REG: u8 = 17;
pub const BT_OP_GET_AFH_MAP_L: u8 = 30;
pub const BT_OP_GET_AFH_MAP_M: u8 = 31;
pub const BT_OP_GET_AFH_MAP_H: u8 = 32;
pub const BT_OP_GET_BT_COEX_SUPPORTED_FEATURE: u8 = 42;
pub const BT_OP_GET_BT_COEX_SUPPORTED_VERSION: u8 = 43;
pub const BT_OP_GET_BT_ANT_DET_VAL: u8 = 44;
pub const BT_OP_GET_BT_BLE_SCAN_PARA: u8 = 45;
pub const BT_OP_GET_BT_BLE_SCAN_TYPE: u8 = 46;
pub const BT_OP_GET_BT_DEVICE_INFO: u8 = 48;
pub const BT_OP_GET_BT_FORBIDDEN_SLOT_VAL: u8 = 49;

/// `enum btc_mp_h2c_req_num`.
pub const BT_SEQ_DONT_CARE: u8 = 0;
pub const BT_SEQ_GET_BT_VERSION: u8 = 0xe;
pub const BT_SEQ_GET_AFH_MAP_L: u8 = 0x5;
pub const BT_SEQ_GET_AFH_MAP_M: u8 = 0x6;
pub const BT_SEQ_GET_AFH_MAP_H: u8 = 0x9;
pub const BT_SEQ_GET_BT_COEX_SUPPORTED_FEATURE: u8 = 0x7;
pub const BT_SEQ_GET_BT_COEX_SUPPORTED_VERSION: u8 = 0x8;
pub const BT_SEQ_GET_BT_ANT_DET_VAL: u8 = 0x2;
pub const BT_SEQ_GET_BT_BLE_SCAN_PARA: u8 = 0x3;
pub const BT_SEQ_GET_BT_BLE_SCAN_TYPE: u8 = 0x4;
pub const BT_SEQ_GET_BT_DEVICE_INFO: u8 = 0xa;
pub const BT_SEQ_GET_BT_FORB_SLOT_VAL: u8 = 0xb;

/// `halbtc_send_bt_mp_operation`'s `req_num` for an op code.
pub const fn mp_req_num(op: u8) -> u8 {
    match op {
        BT_OP_GET_BT_VERSION => BT_SEQ_GET_BT_VERSION,
        BT_OP_GET_AFH_MAP_L => BT_SEQ_GET_AFH_MAP_L,
        BT_OP_GET_AFH_MAP_M => BT_SEQ_GET_AFH_MAP_M,
        BT_OP_GET_AFH_MAP_H => BT_SEQ_GET_AFH_MAP_H,
        BT_OP_GET_BT_COEX_SUPPORTED_FEATURE => BT_SEQ_GET_BT_COEX_SUPPORTED_FEATURE,
        BT_OP_GET_BT_COEX_SUPPORTED_VERSION => BT_SEQ_GET_BT_COEX_SUPPORTED_VERSION,
        BT_OP_GET_BT_ANT_DET_VAL => BT_SEQ_GET_BT_ANT_DET_VAL,
        BT_OP_GET_BT_BLE_SCAN_PARA => BT_SEQ_GET_BT_BLE_SCAN_PARA,
        BT_OP_GET_BT_BLE_SCAN_TYPE => BT_SEQ_GET_BT_BLE_SCAN_TYPE,
        BT_OP_GET_BT_DEVICE_INFO => BT_SEQ_GET_BT_DEVICE_INFO,
        BT_OP_GET_BT_FORBIDDEN_SLOT_VAL => BT_SEQ_GET_BT_FORB_SLOT_VAL,
        _ => BT_SEQ_DONT_CARE,
    }
}

/// `struct btc_board_info`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoardInfo {
    pub bt_chip_type: ChipType,
    pub pg_ant_num: u8,
    pub btdm_ant_num: u8,
    pub btdm_ant_pos: u8,
    /// 8723B only: 1 ⇒ S0, 0 ⇒ S1.
    pub single_ant_path: u8,
    pub tfbga_package: bool,
    pub rfe_type: u8,
    pub ant_div_cfg: u8,
}

/// `struct btc_bt_info` (the fields the rtlwifi glue and algorithms use).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BtInfo {
    pub bt_disabled: bool,
    pub rssi_adjust_for_agc_table_on: u8,
    pub rssi_adjust_for_1ant_coex_type: u8,
    pub pre_bt_ctrl_agg_buf_size: bool,
    pub bt_busy: bool,
    pub pre_agg_buf_size: u8,
    pub agg_buf_size: u8,
    pub limited_dig: bool,
    pub pre_reject_agg_pkt: bool,
    pub reject_agg_pkt: bool,
    pub bt_ctrl_buf_size: bool,
    pub increase_scan_dev_num: bool,
    pub miracast_plus_bt: bool,
    pub bt_ctrl_agg_buf_size: bool,
    pub bt_tx_rx_mask: bool,
    pub force_to_roam: bool,
    pub bt_real_fw_ver: u16,
    pub bt_fw_ver: u8,
    pub bt_disable_low_pwr: bool,
    pub bt_ctrl_lps: bool,
    pub bt_lps_on: bool,
    pub lps_val: u8,
    pub rpwm_val: u8,
    pub ra_mask: u32,
    pub afh_map_l: u32,
    pub afh_map_m: u32,
    pub afh_map_h: u16,
    pub bt_supported_feature: u32,
    pub bt_supported_version: u32,
    pub bt_device_info: u32,
    pub bt_forb_slot_val: u32,
    pub bt_ant_det_val: u8,
    pub bt_ble_scan_type: u8,
    pub bt_ble_scan_para: u32,
}

/// `struct btc_stack_info`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackInfo {
    pub profile_notified: bool,
    pub hci_version: u16,
    pub num_of_link: u8,
    pub bt_link_exist: bool,
    pub sco_exist: bool,
    pub acl_exist: bool,
    pub a2dp_exist: bool,
    pub hid_exist: bool,
    pub num_of_hid: u8,
    pub pan_exist: bool,
    pub unknown_acl_exist: bool,
    pub min_bt_rssi: i8,
}

/// `struct btc_bt_link_info`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BtLinkInfo {
    pub bt_link_exist: bool,
    pub bt_hi_pri_link_exist: bool,
    pub sco_exist: bool,
    pub sco_only: bool,
    pub a2dp_exist: bool,
    pub a2dp_only: bool,
    pub hid_exist: bool,
    pub hid_only: bool,
    pub pan_exist: bool,
    pub pan_only: bool,
    pub slave_role: bool,
    pub acl_busy: bool,
}

/// `struct btc_statistics`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    pub cnt_bind: u32,
    pub cnt_init_hw_config: u32,
    pub cnt_init_coex_dm: u32,
    pub cnt_ips_notify: u32,
    pub cnt_lps_notify: u32,
    pub cnt_scan_notify: u32,
    pub cnt_connect_notify: u32,
    pub cnt_media_status_notify: u32,
    pub cnt_special_packet_notify: u32,
    pub cnt_bt_info_notify: u32,
    pub cnt_periodical: u32,
    pub cnt_coex_dm_switch: u32,
    pub cnt_stack_operation_notify: u32,
    pub cnt_dbg_ctrl: u32,
    pub cnt_pre_load_firmware: u32,
    pub cnt_power_on: u32,
}

/// `rtlpriv->mac80211.mode` as `halbtc_legacy` / `UNDER_B_MODE` see it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiMode {
    B,
    G,
    /// Any HT / VHT mode.
    N,
}

/// `rtlphy->current_chan_bw`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChanBw {
    Ht20,
    Ht20_40,
    Ht80,
}

/// The driver state `halbtc_get` reads (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WifiInfo {
    /// `opmode == STATION && link_state >= MAC80211_LINKED`.
    pub station_linked: bool,
    /// `link_state == MAC80211_LINKING` (`WIFI_LINK` and `WIFI_ROAM`).
    pub linking: bool,
    /// `opmode == NL80211_IFTYPE_AP`.
    pub ap_mode: bool,
    /// `is_any_client_connect_to_ap`.
    pub ap_client_connected: bool,
    /// `link_info.busytraffic`.
    pub busy: bool,
    /// `link_info.tx_busy_traffic` (`halbtc_is_wifi_uplink`).
    pub tx_busy: bool,
    /// `mac->act_scanning`.
    pub scanning: bool,
    /// `btc_info.in_4way`.
    pub in_4way: bool,
    /// `current_bandtype == BAND_ON_5G`.
    pub under_5g: bool,
    /// `pairwise_enc_algorithm != NO_ENCRYPTION`.
    pub encryption: bool,
    pub mode: WifiMode,
    pub chan_bw: ChanBw,
    /// `rtlphy->current_channel`.
    pub current_channel: u8,
    /// `dm.undec_sm_pwdb`.
    pub undec_sm_pwdb: i32,
    /// `rtlhal->fw_version` / `fw_subversion`.
    pub fw_version: u16,
    pub fw_subversion: u16,
    /// `btc_info.ap_num`.
    pub ap_num: u8,
}

impl Default for WifiInfo {
    fn default() -> Self {
        Self {
            station_linked: false,
            linking: false,
            ap_mode: false,
            ap_client_connected: false,
            busy: false,
            tx_busy: false,
            scanning: false,
            in_4way: false,
            under_5g: false,
            encryption: false,
            mode: WifiMode::N,
            chan_bw: ChanBw::Ht20,
            current_channel: 0,
            undec_sm_pwdb: 0,
            fw_version: 0,
            fw_subversion: 0,
            ap_num: 0,
        }
    }
}

impl WifiInfo {
    /// `BTC_GET_BL_WIFI_CONNECTED`.
    pub const fn connected(&self) -> bool {
        self.station_linked || self.ap_client_connected
    }
    /// `halbtc_get_wifi_bw`.
    pub const fn bw(&self) -> WifiBw {
        match (self.mode, self.chan_bw) {
            (WifiMode::B | WifiMode::G, _) => WifiBw::Legacy,
            (_, ChanBw::Ht20) => WifiBw::Ht20,
            (_, ChanBw::Ht20_40) => WifiBw::Ht40,
            (_, ChanBw::Ht80) => WifiBw::Ht80,
        }
    }
    /// `BTC_GET_U4_WIFI_TRAFFIC_DIRECTION`.
    pub const fn traffic_dir(&self) -> TrafficDir {
        if self.tx_busy {
            TrafficDir::Tx
        } else {
            TrafficDir::Rx
        }
    }
    /// `BTC_GET_U4_WIFI_FW_VER`.
    pub const fn fw_ver(&self) -> u32 {
        ((self.fw_version as u32) << 16) | self.fw_subversion as u32
    }
    /// `halbtc_get_wifi_link_status`: `[31:16]` connected ports, `[15:0]`
    /// port bits (no P2P).
    pub const fn link_status(&self) -> u32 {
        let mut bits = 0;
        let mut ports = 0;
        if self.station_linked {
            bits |= WIFI_STA_CONNECTED;
            ports += 1;
        }
        if self.ap_client_connected {
            bits |= WIFI_AP_CONNECTED;
            ports += 1;
        }
        (ports << 16) | bits
    }
    /// `halbtc_get_wifi_central_chnl`.
    pub const fn central_chnl(&self) -> u8 {
        if self.current_channel != 0 {
            self.current_channel
        } else {
            1
        }
    }
    /// `BTC_GET_BL_WIFI_UNDER_B_MODE`.
    pub const fn under_b_mode(&self) -> bool {
        matches!(self.mode, WifiMode::B)
    }
}

/// The BT LPS control `rtl8723be_set_fw_pwrmode_cmd` reads through
/// `rtl_btc_is_bt_ctrl_lps` / `is_bt_lps_on` / `get_lps_val` /
/// `get_rpwm_val`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpsCtrl {
    pub bt_ctrl_lps: bool,
    pub bt_lps_on: bool,
    pub lps_val: u8,
    pub rpwm_val: u8,
}

/// `rtl_btc_get_ampdu_cfg` (what `rtl_rx_ampdu_apply` reads).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmpduCfg {
    pub reject_agg: bool,
    pub ctrl_agg_size: bool,
    pub agg_size: u8,
}

/// One C2H `BT_MP` body as `rtl_c2h_content_parsing` hands it on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpReport {
    pub bytes: [u8; 16],
    pub len: u8,
}

impl MpReport {
    pub fn new(body: &[u8]) -> Self {
        let mut bytes = [0; 16];
        let n = body.len().min(16);
        bytes[..n].copy_from_slice(&body[..n]);
        Self {
            bytes,
            len: n as u8,
        }
    }
    pub fn body(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// The `btc_coexist` function pointers that reach the driver.
#[allow(async_fn_in_trait)]
pub trait Hal {
    /// `rtl_read_byte` / `rtl_read_word` / `rtl_read_dword`.
    fn read8(&mut self, reg: u16) -> Result<u8, Error>;
    fn read16(&mut self, reg: u16) -> Result<u16, Error>;
    fn read32(&mut self, reg: u16) -> Result<u32, Error>;
    /// `rtl_write_byte` / `rtl_write_word` / `rtl_write_dword`.
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error>;
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), Error>;
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error>;
    /// `rtl_set_rfreg` / `rtl_get_rfreg`.
    async fn set_rf(&mut self, path: u8, reg: u32, mask: u32, data: u32) -> Result<(), Error>;
    async fn get_rf(&mut self, path: u8, reg: u32, mask: u32) -> Result<u32, Error>;
    /// `rtlpriv->cfg->ops->fill_h2c_cmd`.
    async fn fill_h2c(&mut self, id: u8, cmd: &[u8]) -> Result<(), Error>;
    /// Wait up to `wait_ms` for the next C2H `BT_MP` body (`None` on
    /// timeout).
    async fn wait_bt_mp(&mut self, wait_ms: u32) -> Result<Option<MpReport>, Error>;
    /// `mdelay`.
    async fn delay_ms(&mut self, ms: u32);
    /// `rtl_lps_leave(hw, false)` with the BT LPS control in effect;
    /// returns the `SETPWRMODE` body sent (for `rtl_btc_record_pwr_mode`).
    async fn lps_leave(&mut self, ctrl: LpsCtrl) -> Result<Option<[u8; 7]>, Error>;
    /// `rtl_lps_enter(hw, false)`.
    async fn lps_enter(&mut self, ctrl: LpsCtrl) -> Result<Option<[u8; 7]>, Error>;
    /// `rtl_rx_ampdu_apply`.
    fn rx_ampdu_apply(&mut self, cfg: AmpduCfg);
    /// Monotonic milliseconds (`jiffies_to_msecs(jiffies)`).
    fn now_ms(&mut self) -> u64;
}

/// `struct btc_coexist` state.
#[derive(Clone, Debug)]
pub struct BtCoexist {
    pub binded: bool,
    pub board_info: BoardInfo,
    pub bt_info: BtInfo,
    pub stack_info: StackInfo,
    pub chip_interface: ChipInterface,
    pub bt_link_info: BtLinkInfo,
    pub auto_report_1ant: bool,
    pub auto_report_2ant: bool,
    pub dbg_mode_1ant: bool,
    pub dbg_mode_2ant: bool,
    pub initialized: bool,
    pub stop_coex_dm: bool,
    pub manual_control: bool,
    pub statistics: Statistics,
    pub pwr_mode_val: [u8; 10],
    /// `rtl_get_hwpg_bt_exist` (`btc_info.btcoexist`).
    pub bt_exist: bool,
    pub wifi: WifiInfo,
    agg_pre_time: Option<u64>,
}

/// The `btc_info` facts `exhalbtc_bind_bt_coex_withadapter` reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwPg {
    /// `btc_info.btcoexist`.
    pub bt_exist: bool,
    /// `rtl_get_hwpg_ant_num`: 2 for `ANT_X2`, else 1.
    pub ant_num: u8,
    /// `btc_info.single_ant_path`.
    pub single_ant_path: u8,
    /// `btc_info.bt_type` already mapped by `exhalbtc_set_chip_type`.
    pub chip_type: ChipType,
    /// `rtlhal->package_type`.
    pub package_type: u8,
    /// `rtlhal->rfe_type`.
    pub rfe_type: u8,
    pub interface: ChipInterface,
}

impl HwPg {
    /// The RTL8723BE facts (`rtl8723be_read_bt_coexist_info_from_hwpg`:
    /// `bt_type = BT_RTL8723B`; PCI; `rfe_type` is never set ⇒ 0).
    pub fn rtl8723be(a: &crate::rtlwifi::rtl8723be::adapter::Adapter) -> Self {
        use crate::rtlwifi::rtl8723be::adapter::{AntNum, AntPath};
        Self {
            bt_exist: a.bt_coexist,
            ant_num: match a.ant_num {
                AntNum::X2 => 2,
                AntNum::X1 => 1,
            },
            single_ant_path: match a.single_ant_path {
                AntPath::Main => 0,
                AntPath::Aux => 1,
            },
            chip_type: ChipType::Rtl8723b,
            package_type: a.package_type,
            rfe_type: 0,
            interface: ChipInterface::Pci,
        }
    }
}

impl BtCoexist {
    /// `rtl_btc_init_variables` → `exhalbtc_initlize_variables` (agg buf
    /// size 5) then `exhalbtc_bind_bt_coex_withadapter`.
    pub fn bind(pg: HwPg) -> Self {
        let bt_info = BtInfo {
            agg_buf_size: 5,
            ..BtInfo::default()
        };
        // package 0 / 1 are not TFBGA.
        let tfbga_package = !matches!(pg.package_type, 0 | 1);
        Self {
            binded: true,
            board_info: BoardInfo {
                bt_chip_type: pg.chip_type,
                pg_ant_num: pg.ant_num,
                btdm_ant_num: pg.ant_num,
                btdm_ant_pos: BTC_ANTENNA_AT_MAIN_PORT,
                single_ant_path: pg.single_ant_path,
                tfbga_package,
                rfe_type: pg.rfe_type,
                ant_div_cfg: 0,
            },
            bt_info,
            stack_info: StackInfo::default(),
            chip_interface: pg.interface,
            bt_link_info: BtLinkInfo::default(),
            auto_report_1ant: false,
            auto_report_2ant: false,
            dbg_mode_1ant: false,
            dbg_mode_2ant: false,
            initialized: false,
            stop_coex_dm: false,
            manual_control: false,
            statistics: Statistics {
                cnt_bind: 1,
                ..Statistics::default()
            },
            pwr_mode_val: [0; 10],
            bt_exist: pg.bt_exist,
            wifi: WifiInfo::default(),
            agg_pre_time: None,
        }
    }

    /// `halbtc_is_bt_coexist_available`.
    pub const fn available(&self) -> bool {
        self.binded
    }

    /// `exhalbtc_set_ant_num(BT_COEX_ANT_TYPE_ANTDIV / DETECTED)`.
    pub fn set_ant_num_detected(&mut self, ant_num: u8, ant_sel_aux: bool) {
        self.board_info.btdm_ant_num = ant_num;
        self.board_info.btdm_ant_pos = if ant_sel_aux {
            BTC_ANTENNA_AT_AUX_PORT
        } else {
            BTC_ANTENNA_AT_MAIN_PORT
        };
    }

    /// `rtl_btc_record_pwr_mode`.
    pub fn record_pwr_mode(&mut self, buf: &[u8]) {
        let n = buf.len().min(self.pwr_mode_val.len());
        self.pwr_mode_val[..n].copy_from_slice(&buf[..n]);
    }

    /// `rtl_btc_is_bt_ctrl_lps` / `is_bt_lps_on` / `get_lps_val` /
    /// `get_rpwm_val`.
    pub const fn lps_ctrl(&self) -> LpsCtrl {
        LpsCtrl {
            bt_ctrl_lps: self.bt_info.bt_ctrl_lps,
            bt_lps_on: self.bt_info.bt_lps_on,
            lps_val: self.bt_info.lps_val,
            rpwm_val: self.bt_info.rpwm_val,
        }
    }

    /// `rtl_btc_get_ampdu_cfg`.
    pub const fn ampdu_cfg(&self) -> AmpduCfg {
        AmpduCfg {
            reject_agg: self.bt_info.reject_agg_pkt,
            ctrl_agg_size: self.bt_info.bt_ctrl_agg_buf_size,
            agg_size: self.bt_info.agg_buf_size,
        }
    }

    /// `rtl_btc_is_limited_dig`.
    pub const fn is_limited_dig(&self) -> bool {
        self.bt_info.limited_dig
    }

    /// `rtl_btc_is_bt_disabled`.
    pub const fn is_bt_disabled(&self) -> bool {
        self.bt_info.bt_disabled
    }

    /// `exhalbtc_update_min_bt_rssi`.
    pub fn update_min_bt_rssi(&mut self, rssi: i8) {
        if self.available() {
            self.stack_info.min_bt_rssi = rssi;
        }
    }

    /// `rtl_btc_btmpinfo_notify`; true where Linux `complete()`s
    /// `bt_mp_comp`.
    pub fn btmpinfo_notify(&mut self, buf: &[u8]) -> bool {
        // C2H_TRIG_BY_BT_FW = 1.
        if buf.len() < 4 || buf[0] != 1 {
            return false;
        }
        let seq = buf[2] >> 4;
        let le32 = |b: &[u8]| {
            let mut w = [0u8; 4];
            let n = b.len().min(4);
            w[..n].copy_from_slice(&b[..n]);
            u32::from_le_bytes(w)
        };
        let data = &buf[3..];
        let at = |i: usize| u32::from(buf.get(i).copied().unwrap_or(0));
        let bi = &mut self.bt_info;
        match seq {
            BT_SEQ_GET_BT_VERSION => {
                bi.bt_real_fw_ver = (at(3) | at(4) << 8) as u16;
                bi.bt_fw_ver = at(5) as u8;
            }
            BT_SEQ_GET_AFH_MAP_L => bi.afh_map_l = le32(data),
            BT_SEQ_GET_AFH_MAP_M => bi.afh_map_m = le32(data),
            BT_SEQ_GET_AFH_MAP_H => bi.afh_map_h = le32(data) as u16,
            BT_SEQ_GET_BT_COEX_SUPPORTED_FEATURE => bi.bt_supported_feature = at(3) | at(4) << 8,
            BT_SEQ_GET_BT_COEX_SUPPORTED_VERSION => bi.bt_supported_version = at(3) | at(4) << 8,
            BT_SEQ_GET_BT_ANT_DET_VAL => bi.bt_ant_det_val = at(3) as u8,
            BT_SEQ_GET_BT_BLE_SCAN_PARA => {
                bi.bt_ble_scan_para = at(3) | at(4) << 8 | at(5) << 16 | at(6) << 24
            }
            BT_SEQ_GET_BT_BLE_SCAN_TYPE => bi.bt_ble_scan_type = at(3) as u8,
            BT_SEQ_GET_BT_DEVICE_INFO => bi.bt_device_info = le32(data),
            // Linux matches `BT_OP_GET_BT_FORBIDDEN_SLOT_VAL` (49) against
            // a 4-bit seq, so this arm never fires there either.
            BT_OP_GET_BT_FORBIDDEN_SLOT_VAL => bi.bt_forb_slot_val = le32(data),
            _ => {}
        }
        true
    }
}

/// `btcoexist->btc_*` over one borrow of the state and the HAL.
#[derive(Debug)]
pub struct Ctx<'a, H> {
    pub btc: &'a mut BtCoexist,
    pub hal: &'a mut H,
}

impl<'a, H: Hal> Ctx<'a, H> {
    pub fn new(btc: &'a mut BtCoexist, hal: &'a mut H) -> Self {
        Self { btc, hal }
    }

    pub fn read_1byte(&mut self, reg: u16) -> Result<u8, Error> {
        self.hal.read8(reg)
    }
    pub fn read_2byte(&mut self, reg: u16) -> Result<u16, Error> {
        self.hal.read16(reg)
    }
    pub fn read_4byte(&mut self, reg: u16) -> Result<u32, Error> {
        self.hal.read32(reg)
    }
    pub fn write_1byte(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        self.hal.write8(reg, value)
    }
    pub fn write_2byte(&mut self, reg: u16, value: u16) -> Result<(), Error> {
        self.hal.write16(reg, value)
    }
    pub fn write_4byte(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        self.hal.write32(reg, value)
    }

    /// `halbtc_bitmask_write_1byte`.
    pub fn write_1byte_bitmask(&mut self, reg: u16, mask: u32, data: u8) -> Result<(), Error> {
        let mut out = u32::from(data);
        if mask != MASKDWORD {
            let original = u32::from(self.hal.read8(reg)?);
            let shift = (0..=7u32).find(|i| (mask >> i) & 1 != 0).unwrap_or(8);
            out = (original & !mask) | ((out << shift) & mask);
        }
        self.hal.write8(reg, out as u8)
    }

    /// `halbtc_write_local_reg_1byte` (SDIO writes nothing).
    pub fn write_local_reg_1byte(&mut self, reg: u16, data: u8) -> Result<(), Error> {
        match self.btc.chip_interface {
            ChipInterface::Pci | ChipInterface::Usb => self.hal.write8(reg, data),
            _ => Ok(()),
        }
    }

    /// `halbtc_set_bbreg` (`rtl8723_phy_set_bb_reg`).
    pub fn set_bb_reg(&mut self, reg: u16, mask: u32, data: u32) -> Result<(), Error> {
        let value = if mask == MASKDWORD {
            data
        } else {
            (self.hal.read32(reg)? & !mask) | (data << mask.trailing_zeros())
        };
        self.hal.write32(reg, value)
    }

    /// `halbtc_get_bbreg`.
    pub fn get_bb_reg(&mut self, reg: u16, mask: u32) -> Result<u32, Error> {
        Ok((self.hal.read32(reg)? & mask) >> mask.trailing_zeros())
    }

    pub async fn set_rf_reg(
        &mut self,
        path: u8,
        reg: u32,
        mask: u32,
        data: u32,
    ) -> Result<(), Error> {
        self.hal.set_rf(path, reg, mask, data).await
    }

    pub async fn get_rf_reg(&mut self, path: u8, reg: u32, mask: u32) -> Result<u32, Error> {
        self.hal.get_rf(path, reg, mask).await
    }

    /// `halbtc_fill_h2c_cmd`.
    pub async fn fill_h2c(&mut self, id: u8, cmd: &[u8]) -> Result<(), Error> {
        self.hal.fill_h2c(id, cmd).await
    }

    /// `halbtc_send_bt_mp_operation` (8723B has the HW mailbox). Returns
    /// false on a wait timeout.
    pub async fn send_bt_mp_operation(
        &mut self,
        op: u8,
        cmd: &mut [u8; 4],
        wait_ms: u32,
    ) -> Result<bool, Error> {
        let req_num = mp_req_num(op);
        // OperVer 0.
        cmd[0] |= (req_num << 4) & 0xf0;
        cmd[1] = op;
        self.hal.fill_h2c(H2C_BT_MP_OPER, cmd).await?;
        if wait_ms == 0 {
            return Ok(true);
        }
        for _ in 0..MP_WAIT_ROUNDS {
            match self.hal.wait_bt_mp(wait_ms).await? {
                None => return Ok(false),
                Some(report) => {
                    if self.btc.btmpinfo_notify(report.body()) {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// `halbtc_set_bt_reg`: value then address, each waited for.
    pub async fn set_bt_reg(
        &mut self,
        reg_type: BtReg,
        offset: u32,
        value: u32,
    ) -> Result<(), Error> {
        let v = (value as u16).to_le_bytes();
        let mut c1 = [0, 0, v[0], v[1]];
        if !self
            .send_bt_mp_operation(BT_OP_WRITE_REG_VALUE, &mut c1, BT_MP_WAIT_MS)
            .await?
        {
            return Ok(());
        }
        let mut c2 = [0, 0, reg_type as u8, offset as u8];
        self.send_bt_mp_operation(BT_OP_WRITE_REG_ADDR, &mut c2, BT_MP_WAIT_MS)
            .await?;
        Ok(())
    }

    /// `BTC_GET_U4_BT_PATCH_VER` → `halbtc_get_bt_patch_version`.
    pub async fn bt_patch_version(&mut self) -> Result<u32, Error> {
        if self.btc.bt_info.bt_real_fw_ver == 0 {
            let mut cmd = [0u8; 4];
            self.send_bt_mp_operation(BT_OP_GET_BT_VERSION, &mut cmd, BT_MP_WAIT_MS)
                .await?;
        }
        Ok(u32::from(self.btc.bt_info.bt_real_fw_ver))
    }

    // ── halbtc_get (non-trivial cases; the rest read `btc.wifi`) ──

    /// `BTC_GET_BL_HS_OPERATION` (always false on rtlwifi).
    pub const fn hs_operation(&self) -> bool {
        false
    }
    /// `BTC_GET_U1_LPS_MODE`.
    pub const fn lps_mode(&self) -> u8 {
        self.btc.pwr_mode_val[0]
    }
    /// `BTC_GET_S4_WIFI_RSSI`.
    pub const fn wifi_rssi(&self) -> i32 {
        self.btc.wifi.undec_sm_pwdb
    }

    // ── halbtc_set actions ──

    /// `halbtc_leave_lps` (`BTC_SET_ACT_LEAVE_LPS`).
    pub async fn leave_lps(&mut self) -> Result<(), Error> {
        if self.btc.wifi.ap_mode {
            return Ok(());
        }
        self.btc.bt_info.bt_ctrl_lps = true;
        self.btc.bt_info.bt_lps_on = false;
        let ctrl = self.btc.lps_ctrl();
        if let Some(cmd) = self.hal.lps_leave(ctrl).await? {
            self.btc.record_pwr_mode(&cmd);
        }
        Ok(())
    }

    /// `halbtc_enter_lps` (`BTC_SET_ACT_ENTER_LPS`).
    pub async fn enter_lps(&mut self) -> Result<(), Error> {
        if self.btc.wifi.ap_mode {
            return Ok(());
        }
        self.btc.bt_info.bt_ctrl_lps = true;
        self.btc.bt_info.bt_lps_on = true;
        let ctrl = self.btc.lps_ctrl();
        if let Some(cmd) = self.hal.lps_enter(ctrl).await? {
            self.btc.record_pwr_mode(&cmd);
        }
        Ok(())
    }

    /// `halbtc_normal_lps` (`BTC_SET_ACT_NORMAL_LPS`).
    pub async fn normal_lps(&mut self) -> Result<(), Error> {
        if self.btc.bt_info.bt_ctrl_lps {
            self.btc.bt_info.bt_lps_on = false;
            let ctrl = self.btc.lps_ctrl();
            if let Some(cmd) = self.hal.lps_leave(ctrl).await? {
                self.btc.record_pwr_mode(&cmd);
            }
            self.btc.bt_info.bt_ctrl_lps = false;
        }
        Ok(())
    }

    /// `halbtc_pre_normal_lps` (`BTC_SET_ACT_PRE_NORMAL_LPS`).
    pub async fn pre_normal_lps(&mut self) -> Result<(), Error> {
        if self.btc.bt_info.bt_ctrl_lps {
            self.btc.bt_info.bt_lps_on = false;
            let ctrl = self.btc.lps_ctrl();
            if let Some(cmd) = self.hal.lps_leave(ctrl).await? {
                self.btc.record_pwr_mode(&cmd);
            }
        }
        Ok(())
    }

    /// `halbtc_post_normal_lps` (`BTC_SET_ACT_POST_NORMAL_LPS`).
    pub fn post_normal_lps(&mut self) {
        self.btc.bt_info.bt_ctrl_lps = false;
    }

    /// `halbtc_disable_low_power` (`BTC_SET_ACT_DISABLE_LOW_POWER`).
    pub fn disable_low_power(&mut self, disable: bool) {
        self.btc.bt_info.bt_disable_low_pwr = disable;
    }

    /// `BTC_SET_ACT_AGGREGATE_CTRL` → `halbtc_aggregation_check`.
    pub fn aggregation_check(&mut self) {
        let now = self.hal.now_ms();
        if let Some(pre) = self.btc.agg_pre_time {
            if now.wrapping_sub(pre) <= 8000 {
                return;
            }
        }
        self.btc.agg_pre_time = Some(now);
        let bi = &mut self.btc.bt_info;
        if bi.reject_agg_pkt {
            // Linux records the state but never applies on this branch.
            bi.pre_reject_agg_pkt = bi.reject_agg_pkt;
            return;
        }
        let mut act = false;
        if bi.pre_reject_agg_pkt {
            act = true;
            bi.pre_reject_agg_pkt = bi.reject_agg_pkt;
        }
        if bi.pre_bt_ctrl_agg_buf_size != bi.bt_ctrl_agg_buf_size {
            act = true;
            bi.pre_bt_ctrl_agg_buf_size = bi.bt_ctrl_agg_buf_size;
        }
        if bi.bt_ctrl_agg_buf_size {
            if bi.pre_agg_buf_size != bi.agg_buf_size {
                act = true;
            }
            bi.pre_agg_buf_size = bi.agg_buf_size;
        }
        if act {
            let cfg = self.btc.ampdu_cfg();
            self.hal.rx_ampdu_apply(cfg);
        }
    }

    /// `rtl_btc_is_disable_edca_turbo`: forces EDCA BE 0x504 to
    /// `0x5ea42b` (uplink and downlink alike); always true.
    pub fn is_disable_edca_turbo(&mut self) -> Result<bool, Error> {
        const EDCA_BT_HS: u32 = 0x005e_a42b;
        if self.hal.read32(0x504)? != EDCA_BT_HS {
            self.hal.write32(0x504, EDCA_BT_HS)?;
        }
        Ok(true)
    }

    // ── exhalbtc_* / rtl_btc_* entry points ──

    /// `rtl_btc_power_on_setting` → `exhalbtc_power_on_setting`.
    pub async fn power_on_setting<A: Algorithm>(&mut self, a: &mut A) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_power_on += 1;
        a.power_on_setting(self).await
    }

    /// `exhalbtc_pre_load_firmware`.
    pub async fn pre_load_firmware<A: Algorithm>(&mut self, a: &mut A) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_pre_load_firmware += 1;
        a.pre_load_firmware(self).await
    }

    /// `rtl_btc_init_hw_config`: `exhalbtc_init_hw_config(!bt_exist)` then
    /// `exhalbtc_init_coex_dm`.
    pub async fn init_hw_config<A: Algorithm>(&mut self, a: &mut A) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_init_hw_config += 1;
        let wifi_only = !self.btc.bt_exist;
        a.init_hw_config(self, wifi_only).await?;
        self.btc.statistics.cnt_init_coex_dm += 1;
        a.init_coex_dm(self).await?;
        self.btc.initialized = true;
        Ok(())
    }

    /// `rtl_btc_ips_notify(rf_off ? ERFOFF : ERFON)`: the IPS notify, then
    /// on `ERFON` a scan start + finish.
    pub async fn ips_notify<A: Algorithm>(&mut self, a: &mut A, rf_off: bool) -> Result<(), Error> {
        if self.btc.available() {
            self.btc.statistics.cnt_ips_notify += 1;
            if !self.btc.manual_control {
                let ty = if rf_off { Ips::Enter } else { Ips::Leave };
                a.ips_notify(self, ty).await?;
            }
        }
        if !rf_off {
            self.scan_notify(a, true).await?;
            self.scan_notify(a, false).await?;
        }
        Ok(())
    }

    /// `exhalbtc_lps_notify(active ? EACTIVE : …)`.
    pub async fn lps_notify<A: Algorithm>(&mut self, a: &mut A, active: bool) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_lps_notify += 1;
        if self.btc.manual_control {
            return Ok(());
        }
        let ty = if active { Lps::Disable } else { Lps::Enable };
        a.lps_notify(self, ty).await
    }

    /// `exhalbtc_scan_notify`.
    pub async fn scan_notify<A: Algorithm>(&mut self, a: &mut A, start: bool) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_scan_notify += 1;
        if self.btc.manual_control {
            return Ok(());
        }
        let ty = if start { Scan::Start } else { Scan::Finish };
        a.scan_notify(self, ty).await
    }

    /// `exhalbtc_connect_notify`.
    pub async fn connect_notify<A: Algorithm>(
        &mut self,
        a: &mut A,
        start: bool,
    ) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_connect_notify += 1;
        if self.btc.manual_control {
            return Ok(());
        }
        let ty = if start {
            Associate::Start
        } else {
            Associate::Finish
        };
        a.connect_notify(self, ty).await
    }

    /// `exhalbtc_mediastatus_notify`.
    pub async fn media_status_notify<A: Algorithm>(
        &mut self,
        a: &mut A,
        connect: bool,
    ) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_media_status_notify += 1;
        if self.btc.manual_control {
            return Ok(());
        }
        let ty = if connect {
            Media::Connect
        } else {
            Media::Disconnect
        };
        a.media_status_notify(self, ty).await
    }

    /// `exhalbtc_special_packet_notify` (`Unknown` returns before the
    /// algorithm).
    pub async fn special_packet_notify<A: Algorithm>(
        &mut self,
        a: &mut A,
        pkt: Packet,
    ) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_special_packet_notify += 1;
        if self.btc.manual_control || pkt == Packet::Unknown {
            return Ok(());
        }
        a.special_packet_notify(self, pkt).await
    }

    /// `rtl_btc_btinfo_notify` → `exhalbtc_bt_info_notify`.
    pub async fn bt_info_notify<A: Algorithm>(
        &mut self,
        a: &mut A,
        buf: &[u8],
    ) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_bt_info_notify += 1;
        a.bt_info_notify(self, buf).await
    }

    /// `exhalbtc_halt_notify` (unbinds).
    pub async fn halt_notify<A: Algorithm>(&mut self, a: &mut A) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        let r = a.halt_notify(self).await;
        self.btc.binded = false;
        r
    }

    /// `exhalbtc_pnp_notify`.
    pub async fn pnp_notify<A: Algorithm>(&mut self, a: &mut A, state: Pnp) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        a.pnp_notify(self, state).await
    }

    /// `rtl_btc_periodical` → `exhalbtc_periodical`.
    pub async fn periodical<A: Algorithm>(&mut self, a: &mut A) -> Result<(), Error> {
        if !self.btc.available() {
            return Ok(());
        }
        self.btc.statistics.cnt_periodical += 1;
        a.periodical(self).await
    }
}

/// The `ex_btc<chip><n>ant_*` handlers one algorithm provides.
#[allow(async_fn_in_trait)]
pub trait Algorithm {
    async fn power_on_setting<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<(), Error>;
    async fn pre_load_firmware<H: Hal>(&mut self, _cx: &mut Ctx<'_, H>) -> Result<(), Error> {
        Ok(())
    }
    async fn init_hw_config<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        wifi_only: bool,
    ) -> Result<(), Error>;
    async fn init_coex_dm<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<(), Error>;
    async fn ips_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Ips) -> Result<(), Error>;
    async fn lps_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Lps) -> Result<(), Error>;
    async fn scan_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, ty: Scan) -> Result<(), Error>;
    async fn connect_notify<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        ty: Associate,
    ) -> Result<(), Error>;
    async fn media_status_notify<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        ty: Media,
    ) -> Result<(), Error>;
    async fn special_packet_notify<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        ty: Packet,
    ) -> Result<(), Error>;
    async fn bt_info_notify<H: Hal>(
        &mut self,
        cx: &mut Ctx<'_, H>,
        buf: &[u8],
    ) -> Result<(), Error>;
    async fn halt_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<(), Error>;
    async fn pnp_notify<H: Hal>(&mut self, cx: &mut Ctx<'_, H>, state: Pnp) -> Result<(), Error>;
    async fn periodical<H: Hal>(&mut self, cx: &mut Ctx<'_, H>) -> Result<(), Error>;
}
