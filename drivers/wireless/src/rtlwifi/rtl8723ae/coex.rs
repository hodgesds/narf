// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723AE Bluetooth-coexistence owner (pass 1).
//!
//! Linux `rtl8723ae/{hal_btc,hal_bt_coexist}.{c,h}` splits the 8723A
//! coexistence mechanism in two: the watchdog DM
//! (`rtl8723e_dm_bt_coexist_8723`, `dm.c`) runs the 1-ant / 2-ant
//! mechanism trees over HW-counter monitors, and the firmware-event path
//! (`rtl_8723e_c2h_command_handle`, `hal_btc.c`) parses `BtInfo` and
//! triggers the periodical when BTC status holds (always true on this
//! chip: `rtl8723e_get_btc_status` in `sw.c` returns true
//! unconditionally). This module is the pass-1 owner: board binding,
//! `BtInfo` ingestion exactly per `rtl8723e_dm_bt_parse_bt_info`, the
//! periodical decision (the shared `btcoex` matrix), and the DM
//! primitives the trees call. It mirrors the `rtl8821ae/coex.rs` pass-1
//! precedent: a decision owner with hooks. The mechanism trees that
//! consume those primitives live in `dm.rs`.
//!
//! ## What is ported here (grounded)
//!
//! | Linux source | NARF item |
//! |---|---|
//! | `hal_bt_coexist.c` `_rtl8723_dm_bt_check_wifi_state` | [`Owner::check_wifi_state`] |
//! | `hal_bt_coexist.c` `rtl8723e_dm_bt_check_coex_rssi_state{,1}` | [`Owner::rssi_state`], [`Owner::rssi_state1`] (levels 2 and 3, `BT_FW_COEX_THRESH_TOL` 6) |
//! | `hal_bt_coexist.c` `rtl8723e_dm_bt_balance` (H2C `0x0c`) | [`Owner::balance`] |
//! | `hal_bt_coexist.c` `rtl8723e_dm_bt_agc_table` (MMIO `0xc78` table) | [`Owner::agc_table`] |
//! | `hal_bt_coexist.c` `rtl8723e_dm_bt_bb_back_off_level` (MMIO `0xc04`) | [`Owner::bb_back_off`] |
//! | `hal_bt_coexist.c` `rtl8723e_dm_bt_{fw,sw,hw}_coex_all_off` wrappers | [`Owner::coex_all_off`] (see the flag caveat below) |
//! | `hal_bt_coexist.c` `rtl8723e_dm_bt_is_coexist_state_changed` | [`Owner::is_coexist_state_changed`] |
//! | `hal_bt_coexist.c` `rtl8723e_dm_bt_is_wifi_up_link` | [`Owner::is_wifi_up_link`] |
//! | `hal_btc.c` `rtl8723e_dm_bt_parse_bt_info` | [`Owner::ingest`] |
//! | `hal_btc.c` c2h dispatch + `btc_periodical` trigger | [`Owner::periodical`] |
//!
//! ## Deliberately NOT ported here
//!
//! - Nothing of the RF half is skipped any more: `agc_table` programs
//!   `RF_RX_AGC_HP` (`0x12`) / `RF_RX_G1` (`0x1a`) on `RF90_PATH_A`
//!   through the shared `rtl8723com` LSSI writer
//!   ([`crate::rtlwifi::rtl8723be::phy::rf_serial_write`], the body of
//!   `rtl8723_phy_rf_serial_write`; every coex RF write uses the full
//!   `0xfffff` mask, so `rtl8723e_phy_set_rf_reg` reduces to it). The
//!   LPF-corner step in `dm.rs` uses the same writer.
//! - No H2C TDMA push: the shared `btcoex::H2C_BT_TDMA` (`0x66`) is the
//!   8723B element-id (`rtl8723be/fw.h::H2C_8723B_B_TYPE_TDMA`), not an
//!   8723A command. The 8723A antenna-sharing actions are `balance`,
//!   `agc_table` and `bb_back_off` above; the periodical returns the
//!   matrix decision for the station owner to record, it does not push
//!   a TDMA pattern the chip would not understand.
//!
//! The full 1-ant / 2-ant mechanism trees and the `_8723a` command
//! sequences behind the all-off wrappers used to be listed here as a
//! follow-up tree lane; they now live in `dm.rs`. [`Owner::coex_all_off`]
//! keeps its wrapper semantics (idempotent flags plus the two grounded
//! SW sub-commands); the tree's full sequences are the separate
//! `all_off_*` methods, and no reader consults the wrapper flags as
//! hardware state.

use super::adapter::{AntNum, BtInfo as AdapterBtInfo};
use super::c2h::BtInfo as C2hBtInfo;
use crate::rtlwifi::btcoex::btc::{BtCoexist, ChipInterface, ChipType, HwPg};
use crate::rtlwifi::btcoex::{pattern_for, BtState, TdmaPattern, WifiState};
use crate::rtlwifi::firmware_transport::{Error as FwError, Io};
use crate::rtlwifi::rtl8723be::phy::{rf_serial_write, Path as RfPath};

/// `hal_bt_coexist.h::BT_FW_COEX_THRESH_TOL`.
pub const RSSI_TOL: i32 = 6;

/// AGC table write port (`hal_bt_coexist.c::rtl8723e_dm_bt_agc_table`):
/// Linux writes all five dwords to this one register.
pub const REG_AGC_TABLE: u16 = 0x0c78;
/// `reg.h::RF_RX_AGC_HP`.
pub const RF_RX_AGC_HP: u32 = 0x12;
/// `reg.h::RF_RX_G1`.
pub const RF_RX_G1: u32 = 0x1a;
/// RF half of `BT_AGCTABLE_OFF`: `(reg, value)` on `RF90_PATH_A`, mask
/// `0xfffff`, in Linux order.
pub const AGC_RF_OFF: [(u32, u32); 5] = [
    (RF_RX_AGC_HP, 0x32000),
    (RF_RX_AGC_HP, 0x71000),
    (RF_RX_AGC_HP, 0xb0000),
    (RF_RX_AGC_HP, 0xfc000),
    (RF_RX_G1, 0x30355),
];
/// RF half of `BT_AGCTABLE_ON`.
pub const AGC_RF_ON: [(u32, u32); 5] = [
    (RF_RX_AGC_HP, 0xdc000),
    (RF_RX_AGC_HP, 0x90000),
    (RF_RX_AGC_HP, 0x51000),
    (RF_RX_AGC_HP, 0x12000),
    (RF_RX_G1, 0x00355),
];
/// AGC table, coex OFF: `0x641c0001, 0x631d0001, 0x621e0001, 0x611f0001,
/// 0x60200001` (`BT_AGCTABLE_OFF`).
pub const AGC_TABLE_OFF: [u32; 5] = [0x641c0001, 0x631d0001, 0x621e0001, 0x611f0001, 0x60200001];
/// AGC table, coex ON: `0x4e1c0001, 0x4d1d0001, 0x4c1e0001, 0x4b1f0001,
/// 0x4a200001` (`BT_AGCTABLE_ON`).
pub const AGC_TABLE_ON: [u32; 5] = [0x4e1c0001, 0x4d1d0001, 0x4c1e0001, 0x4b1f0001, 0x4a200001];

/// BB back-off register (`hal_bt_coexist.c::rtl8723e_dm_bt_bb_back_off_level`).
pub const REG_BB_BACKOFF: u16 = 0x0c04;
/// Back-off level, coex OFF (`BT_BB_BACKOFF_OFF`).
pub const BB_BACKOFF_OFF: u32 = 0x3a05611;
/// Back-off level, coex ON (`BT_BB_BACKOFF_ON`).
pub const BB_BACKOFF_ON: u32 = 0x3a07611;

/// Balance H2C element-id (`hal_bt_coexist.c::rtl8723e_dm_bt_balance`).
pub const H2C_BALANCE: u8 = 0x0c;
/// H2C mailbox registers (shared 92C family: `h2c.rs` / `rtl8723be/h2c.rs`).
pub const REG_HMETFR: u16 = 0x01cc;
/// First H2C box register.
pub const REG_HMEBOX_0: u16 = 0x01d0;
/// First H2C box-extension register.
pub const REG_HMEBOX_EXT_0: u16 = 0x01f0;
/// HMETFR free-box poll bound, mirroring `rtl8723be/h2c.rs`.
const HMETFR_CHECKS: u32 = 100;

/// `hal_bt_coexist.h` coexistence-state bits (`cstate`).
pub mod state {
    /// BT 3.0 operation on.
    pub const BT30: u32 = 1 << 0;
    /// Wi-Fi HT20.
    pub const WIFI_HT20: u32 = 1 << 1;
    /// Wi-Fi HT40.
    pub const WIFI_HT40: u32 = 1 << 2;
    /// Wi-Fi legacy (B/G).
    pub const WIFI_LEGACY: u32 = 1 << 3;
    /// Wi-Fi RSSI low.
    pub const WIFI_RSSI_LOW: u32 = 1 << 4;
    /// Wi-Fi RSSI medium.
    pub const WIFI_RSSI_MEDIUM: u32 = 1 << 5;
    /// Wi-Fi RSSI high.
    pub const WIFI_RSSI_HIGH: u32 = 1 << 6;
    /// Decrease BT power (live Wi-Fi link).
    pub const DEC_BT_POWER: u32 = 1 << 7;
    /// Wi-Fi idle.
    pub const WIFI_IDLE: u32 = 1 << 8;
    /// Wi-Fi uplink traffic.
    pub const WIFI_UPLINK: u32 = 1 << 9;
    /// Wi-Fi downlink traffic.
    pub const WIFI_DOWNLINK: u32 = 1 << 10;
    /// BT inquiry / page.
    pub const BT_INQ_PAGE: u32 = 1 << 11;
    /// BT idle.
    pub const BT_IDLE: u32 = 1 << 12;
    /// BT uplink traffic.
    pub const BT_UPLINK: u32 = 1 << 13;
    /// BT downlink traffic.
    pub const BT_DOWNLINK: u32 = 1 << 14;
    /// Hold for BT operation (inquiry/page/pairing).
    pub const HOLD_FOR_BT_OPERATION: u32 = 1 << 15;
    /// BT RSSI low.
    pub const BT_RSSI_LOW: u32 = 1 << 19;
    /// BT profile: HID.
    pub const PROFILE_HID: u32 = 1 << 20;
    /// BT profile: A2DP.
    pub const PROFILE_A2DP: u32 = 1 << 21;
    /// BT profile: PAN.
    pub const PROFILE_PAN: u32 = 1 << 22;
    /// BT profile: SCO.
    pub const PROFILE_SCO: u32 = 1 << 23;
    /// Wi-Fi RSSI-1 low.
    pub const WIFI_RSSI_1_LOW: u32 = 1 << 24;
    /// Wi-Fi RSSI-1 medium.
    pub const WIFI_RSSI_1_MEDIUM: u32 = 1 << 25;
    /// Wi-Fi RSSI-1 high.
    pub const WIFI_RSSI_1_HIGH: u32 = 1 << 26;
    /// BT-info action: FTP/A2DP.
    pub const BTINFO_B_FTP_A2DP: u32 = 1 << 29;
    /// BT-info action: common.
    pub const BTINFO_COMMON: u32 = 1 << 30;
    /// BT-info action: HID/SCO/eSCO.
    pub const BTINFO_B_HID_SCOESCO: u32 = 1 << 31;
}

/// `hal_bt_coexist.h::BT_RSSI_STATE_*` (shared `btcoex::btc::RssiState`
/// order: High 0, Medium 1, Low 2, StayHigh 3, StayMedium 4, StayLow 5).
pub use crate::rtlwifi::btcoex::btc::RssiState;

/// Wi-Fi traffic / mode inputs to [`Owner::check_wifi_state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WifiTraffic {
    /// `link_info.busytraffic`.
    pub busy: bool,
    /// `link_info.tx_busy_traffic`.
    pub tx_busy: bool,
    /// `link_info.rx_busy_traffic`.
    pub rx_busy: bool,
    /// `mac80211.mode` is B or G (legacy); otherwise HT.
    pub legacy: bool,
    /// `rtlphy->current_chan_bw == HT_CHANNEL_WIDTH_20_40`.
    pub bw40: bool,
    /// `bt_operation_on` module parameter.
    pub bt30: bool,
}

/// The 8723AE coexistence owner: bound `btc_coexist` state, the
/// `hal_bt_coexist.c` DM state, and the current Wi-Fi/BT states the
/// decision matrix reads.
#[derive(Debug)]
pub struct Owner {
    /// `struct btc_coexist` state, bound from the adapter BT facts.
    pub btc: BtCoexist,
    /// Whether the board straps the BT function (`REG_MULTI_FUNC_CTRL`
    /// BIT(18)); the periodical is a no-op without it, mirroring the
    /// watchdog's `if (!bt_coexistence) return` gate.
    pub coexistence: bool,
    /// `bt_ant_num` from the adapter facts (`ANT_X2`/`ANT_X1`).
    pub ant_num: AntNum,
    wifi: WifiState,
    bt: BtState,
    /// `btcoexist.bt_busy` (`BTINFO_B_CONNECTION`).
    pub bt_busy: bool,
    /// `BT_COEX_STATE_BT_IDLE` set (no BT link).
    pub bt_idle: bool,
    /// `BTINFO` inquiry / page bit.
    pub inquiry_page: bool,
    /// `c2h_bt_info_req_sent`, cleared by every BT info parse.
    pub req_sent: bool,
    /// `bt_retry_cnt` from the last BT info body.
    pub retry_cnt: u8,
    /// `c2h_bt_info_original`: body byte 0 of the last BT info, whose
    /// profile bits the 2-ant dispatch reads (`dm.rs`).
    pub bt_info_original: u8,
    /// High-priority BT TX counter (`0x770` low half).
    pub hp_tx: u32,
    /// High-priority BT RX counter (`0x770` high half).
    pub hp_rx: u32,
    /// Low-priority BT TX counter (`0x774` low half).
    pub lp_tx: u32,
    /// Low-priority BT RX counter (`0x774` high half).
    pub lp_rx: u32,
    /// Consecutive all-dead counter reads (`bt_active_zero_cnt`).
    pub bt_active_zero_cnt: u8,
    /// BT currently counts as disabled (`cur_bt_disabled`).
    pub cur_bt_disabled: bool,
    /// Previous disabled state (`pre_bt_disabled`).
    pub pre_bt_disabled: bool,
    /// Inquiry/page window start, monotonic ms (`None` = closed).
    pub inq_page_start_ms: Option<u64>,
    /// LPS counter for the counter monitor's averaging step
    /// (`lps_counter`; no in-tree producer bumps it yet).
    pub lps_counter: u32,
    /// Last applied mechanism setting (`hal_coex_8723.btdm`, for the
    /// `set_bt_dm` dedup).
    pub saved_btdm: super::dm::Btdm,
    /// Dispatched profile case (`bt_profile_case`).
    pub profile_case: super::dm::Mech,
    /// Dispatched profile action (`bt_profile_action`).
    pub profile_action: super::dm::Mech,
    /// Hold for BT operation (`hold_for_bt_operation`; no in-tree
    /// producer sets it yet — `set_bt_dm` honors it when set).
    pub hold_for_bt_operation: bool,
    /// Watchdog mechanism initialized (`init_set`).
    pub mech_init_set: bool,
    /// `btcoexist.bt_rfreg_origin_1e`: RF `0x1e` (`RF_RCK1`, mask
    /// `0xfffff`) captured by the mechanism init; the LPF-corner resume
    /// restores it. `None` until [`Owner::mech_init`] ran.
    pub rf_origin_1e: Option<u32>,
    /// `btcoexist.bt_rfreg_origin_1f`: RF `0x1f` (`RF_RCK2`) bits `[7:4]`
    /// captured by the mechanism init (Linux stores it and never reads it).
    pub rf_origin_1f: Option<u32>,
    /// `btcoexist.cstate`.
    pub cstate: u32,
    /// `btcoexist.cstate_h` (BT counter levels live in bits 0..3).
    pub cstate_h: u32,
    /// Previous `cstate`, for [`Owner::is_coexist_state_changed`].
    pub(crate) prev_cstate: u32,
    /// Previous `cstate_h`, for [`Owner::is_coexist_state_changed`].
    pub(crate) prev_cstate_h: u32,
    /// `link_info.tx_busy_traffic`, for [`Owner::is_wifi_up_link`].
    tx_busy: bool,
    /// `btcoexist.bt_pre_rssi_state` (zero-init = High).
    pre_rssi: RssiState,
    /// `btcoexist.bt_pre_rssi_state1` (zero-init = High).
    pre_rssi1: RssiState,
    /// `balance_on` (`hal_bt_coexist.c`).
    pub balance_on: bool,
    /// AGC table currently programmed ON.
    pub agc_on: bool,
    /// BB back-off currently programmed ON.
    pub backoff_on: bool,
    /// `fw_coexist_all_off` wrapper flag (see the module caveat).
    pub fw_all_off: bool,
    /// `sw_coexist_all_off` wrapper flag (see the module caveat).
    pub sw_all_off: bool,
    /// `hw_coexist_all_off` wrapper flag (see the module caveat).
    pub hw_all_off: bool,
    /// Next H2C box number (`rtlhal->last_hmeboxnum` rotation).
    h2c_next: u8,
}

/// H2C fill failure (mirrors `rtl8723be/h2c.rs` error shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The box never freed within [`HMETFR_CHECKS`] polls.
    CommandTimeout,
    /// Register access failed.
    Access,
    /// Payload empty or longer than 7 bytes.
    State,
}

impl From<FwError> for Error {
    fn from(_: FwError) -> Self {
        Error::Access
    }
}

impl From<crate::rtlwifi::prepare::Error> for Error {
    fn from(_: crate::rtlwifi::prepare::Error) -> Self {
        Error::Access
    }
}

impl Owner {
    /// Bind the owner from the `rtl8723e_read_bt_coexist_info_from_hwpg`
    /// facts. The caller binds only for BT-strapped boards (as
    /// `configure_rtl8821ae_mac` does for 8821AE); `coexistence` is
    /// recorded so the periodical can still gate on it.
    pub fn bind(bt: &AdapterBtInfo) -> Self {
        Self {
            btc: BtCoexist::bind(HwPg {
                bt_exist: bt.coexistence,
                ant_num: match bt.ant_num {
                    AntNum::X2 => 2,
                    AntNum::X1 => 1,
                },
                single_ant_path: 0,
                chip_type: ChipType::Rtl8723a,
                package_type: 0,
                rfe_type: 0,
                interface: ChipInterface::Pci,
            }),
            coexistence: bt.coexistence,
            ant_num: bt.ant_num,
            wifi: WifiState::Idle,
            bt: BtState::Idle,
            bt_busy: false,
            bt_idle: true,
            inquiry_page: false,
            req_sent: false,
            retry_cnt: 0,
            bt_info_original: 0,
            hp_tx: 0,
            hp_rx: 0,
            lp_tx: 0,
            lp_rx: 0,
            bt_active_zero_cnt: 0,
            cur_bt_disabled: false,
            pre_bt_disabled: false,
            inq_page_start_ms: None,
            lps_counter: 0,
            saved_btdm: super::dm::Btdm::default(),
            profile_case: super::dm::Mech::None,
            profile_action: super::dm::Mech::None,
            hold_for_bt_operation: false,
            mech_init_set: false,
            rf_origin_1e: None,
            rf_origin_1f: None,
            cstate: state::BT_IDLE,
            cstate_h: 0,
            prev_cstate: state::BT_IDLE,
            prev_cstate_h: 0,
            tx_busy: false,
            pre_rssi: RssiState::High,
            pre_rssi1: RssiState::High,
            balance_on: false,
            agc_on: false,
            backoff_on: false,
            fw_all_off: false,
            sw_all_off: false,
            hw_all_off: false,
            h2c_next: 0,
        }
    }

    /// Current TDMA pattern from the decision matrix.
    pub fn pattern(&self) -> TdmaPattern {
        pattern_for(self.wifi, self.bt)
    }

    /// Wi-Fi state transition (assoc/scan hook; no producer wired yet).
    pub fn notify_wifi(&mut self, wifi: WifiState) {
        self.wifi = wifi;
    }

    /// `rtl8723e_dm_bt_parse_bt_info` (`hal_btc.c`): clears
    /// `c2h_bt_info_req_sent` and `bt_retry_cnt` first; the original
    /// byte, the retry byte (only when the body carries it — already
    /// applied by `c2h::parse_bt_info`), inquiry/page bit 2 and the
    /// connection bit 0 drive `bt_busy` / idle exactly as Linux.
    pub fn ingest(&mut self, info: &C2hBtInfo) {
        self.req_sent = false;
        self.retry_cnt = info.retry_cnt;
        self.bt_info_original = info.original;
        self.inquiry_page = info.inquiry_page;
        // Note: the parse grounds `bt_busy` / idle only; it does not
        // touch the `BT_INQ_PAGE` cstate bit, so inquiry state lives in
        // the field above and the tree lane decides the cstate bit.
        if info.connected {
            self.bt_busy = true;
            self.bt_idle = false;
            self.cstate &= !state::BT_IDLE;
            // Judgment call: a connected link maps to Streaming (the
            // matrix's "BT active" state) to protect the link;
            // traffic-class refinement is the tree lane's work.
            self.bt = BtState::Streaming;
        } else {
            self.bt_busy = false;
            self.bt_idle = true;
            self.cstate |= state::BT_IDLE;
            self.bt = if info.inquiry_page {
                BtState::Inquiry
            } else {
                BtState::Idle
            };
        }
    }

    /// The c2h periodical trigger (`hal_btc.c` dispatch): BTC status is
    /// always true on 8723AE, so a BT info event always runs the
    /// decision — except on boards without the BT strap, where the
    /// watchdog returns early. Returns the matrix decision and snapshots
    /// the state for [`Owner::is_coexist_state_changed`]; `None` when
    /// the board has no BT function.
    pub fn periodical(&mut self) -> Option<TdmaPattern> {
        if !self.coexistence {
            return None;
        }
        let pattern = self.pattern();
        self.prev_cstate = self.cstate;
        self.prev_cstate_h = self.cstate_h;
        Some(pattern)
    }

    /// `_rtl8723_dm_bt_check_wifi_state`: busytraffic clears idle and
    /// sets/clears uplink/downlink; idle sets idle and clears both.
    /// Legacy mode sets LEGACY and clears HT20/HT40; HT mode clears
    /// LEGACY and sets HT40 iff `bw40`, else HT20. BT30 sets/clears
    /// the BT30 bit.
    pub fn check_wifi_state(&mut self, traffic: &WifiTraffic) {
        self.tx_busy = traffic.tx_busy;
        if traffic.busy {
            self.cstate &= !state::WIFI_IDLE;
            if traffic.tx_busy {
                self.cstate |= state::WIFI_UPLINK;
            } else {
                self.cstate &= !state::WIFI_UPLINK;
            }
            if traffic.rx_busy {
                self.cstate |= state::WIFI_DOWNLINK;
            } else {
                self.cstate &= !state::WIFI_DOWNLINK;
            }
        } else {
            self.cstate |= state::WIFI_IDLE;
            self.cstate &= !state::WIFI_UPLINK;
            self.cstate &= !state::WIFI_DOWNLINK;
        }
        if traffic.legacy {
            self.cstate |= state::WIFI_LEGACY;
            self.cstate &= !state::WIFI_HT20;
            self.cstate &= !state::WIFI_HT40;
        } else {
            self.cstate &= !state::WIFI_LEGACY;
            if traffic.bw40 {
                self.cstate |= state::WIFI_HT40;
                self.cstate &= !state::WIFI_HT20;
            } else {
                self.cstate |= state::WIFI_HT20;
                self.cstate &= !state::WIFI_HT40;
            }
        }
        if traffic.bt30 {
            self.cstate |= state::BT30;
        } else {
            self.cstate &= !state::BT30;
        }
    }

    /// Shared hysteresis core for [`Owner::rssi_state`] and
    /// [`Owner::rssi_state1`]: `level_num` 2 (two levels, `thresh`) or 3
    /// (three levels, `thresh`/`thresh1`); any other level stores High
    /// (0) and leaves the bits untouched, exactly as Linux (whose
    /// `bt_rssi_state` starts at 0). `clear_medium` / `set` / `clear`
    /// select the bit set the variant writes.
    fn rssi_hysteresis(
        pre: RssiState,
        pwdb: i32,
        level_num: u8,
        thresh: i32,
        thresh1: i32,
    ) -> (RssiState, Option<(bool, bool, bool)>) {
        // Returns (new state, Some((low, medium, high)) to write).
        if level_num == 2 {
            if matches!(pre, RssiState::Low | RssiState::StayLow) {
                if pwdb >= thresh + RSSI_TOL {
                    (RssiState::High, Some((false, false, true)))
                } else {
                    (RssiState::StayLow, None)
                }
            } else if pwdb < thresh {
                (RssiState::Low, Some((true, false, false)))
            } else {
                (RssiState::StayHigh, None)
            }
        } else if level_num == 3 {
            if thresh > thresh1 {
                // Threshold error: Linux returns the previous state.
                return (pre, None);
            }
            if matches!(pre, RssiState::Low | RssiState::StayLow) {
                if pwdb >= thresh + RSSI_TOL {
                    (RssiState::Medium, Some((false, true, false)))
                } else {
                    (RssiState::StayLow, None)
                }
            } else if matches!(pre, RssiState::Medium | RssiState::StayMedium) {
                if pwdb >= thresh1 + RSSI_TOL {
                    (RssiState::High, Some((false, false, true)))
                } else if pwdb < thresh {
                    (RssiState::Low, Some((true, false, false)))
                } else {
                    (RssiState::StayMedium, None)
                }
            } else if pwdb < thresh1 {
                (RssiState::Medium, Some((false, true, false)))
            } else {
                (RssiState::StayHigh, None)
            }
        } else {
            (RssiState::High, None)
        }
    }

    /// `rtl8723e_dm_bt_check_coex_rssi_state`: the `WIFI_RSSI_*` bits
    /// (4/5/6) and `bt_pre_rssi_state`. Level 2 clears MEDIUM first.
    pub fn rssi_state(&mut self, pwdb: i32, level_num: u8, thresh: u8, thresh1: u8) -> RssiState {
        if level_num == 2 {
            self.cstate &= !state::WIFI_RSSI_MEDIUM;
        }
        let (next, bits) = Self::rssi_hysteresis(
            self.pre_rssi,
            pwdb,
            level_num,
            i32::from(thresh),
            i32::from(thresh1),
        );
        // Threshold-error early return (level 3, thresh > thresh1):
        // Linux returns the previous state without storing.
        if level_num == 3 && thresh > thresh1 {
            return self.pre_rssi;
        }
        if let Some((low, medium, high)) = bits {
            if low {
                self.cstate |= state::WIFI_RSSI_LOW;
            } else {
                self.cstate &= !state::WIFI_RSSI_LOW;
            }
            if medium {
                self.cstate |= state::WIFI_RSSI_MEDIUM;
            } else {
                self.cstate &= !state::WIFI_RSSI_MEDIUM;
            }
            if high {
                self.cstate |= state::WIFI_RSSI_HIGH;
            } else {
                self.cstate &= !state::WIFI_RSSI_HIGH;
            }
        }
        self.pre_rssi = next;
        next
    }

    /// `rtl8723e_dm_bt_check_coex_rssi_state1`: the `WIFI_RSSI_1_*` bits
    /// (24/25/26) and `bt_pre_rssi_state1`. Level 2 clears MEDIUM first.
    pub fn rssi_state1(&mut self, pwdb: i32, level_num: u8, thresh: u8, thresh1: u8) -> RssiState {
        if level_num == 2 {
            self.cstate &= !state::WIFI_RSSI_1_MEDIUM;
        }
        let (next, bits) = Self::rssi_hysteresis(
            self.pre_rssi1,
            pwdb,
            level_num,
            i32::from(thresh),
            i32::from(thresh1),
        );
        if level_num == 3 && thresh > thresh1 {
            return self.pre_rssi1;
        }
        if let Some((low, medium, high)) = bits {
            if low {
                self.cstate |= state::WIFI_RSSI_1_LOW;
            } else {
                self.cstate &= !state::WIFI_RSSI_1_LOW;
            }
            if medium {
                self.cstate |= state::WIFI_RSSI_1_MEDIUM;
            } else {
                self.cstate &= !state::WIFI_RSSI_1_MEDIUM;
            }
            if high {
                self.cstate |= state::WIFI_RSSI_1_HIGH;
            } else {
                self.cstate &= !state::WIFI_RSSI_1_HIGH;
            }
        }
        self.pre_rssi1 = next;
        next
    }

    /// Fill one H2C command through the box rotation, mirroring
    /// `rtl8723be_fill_h2c_cmd` (`HMETFR` free-box poll, box + extension
    /// split at 3 payload bytes). Payloads longer than 7 bytes or empty
    /// are refused, as in the BE mailbox.
    pub(crate) async fn h2c_fill<I: Io>(
        &mut self,
        io: &I,
        id: u8,
        payload: &[u8],
    ) -> Result<(), Error> {
        if payload.is_empty() || payload.len() > 7 {
            return Err(Error::State);
        }
        let boxnum = self.h2c_next;
        let mut read = false;
        for check in 0..HMETFR_CHECKS {
            if check != 0 {
                io.delay_us(10).await;
            }
            let hmetfr = io.read8(REG_HMETFR)?;
            if hmetfr == 0xff {
                return Err(Error::Access);
            }
            if (hmetfr >> boxnum) & 1 == 0 {
                read = true;
                break;
            }
        }
        if !read {
            return Err(Error::CommandTimeout);
        }
        let base = REG_HMEBOX_0 + u16::from(boxnum) * 4;
        let mut content = [0u8; 4];
        content[0] = id;
        if payload.len() > 3 {
            let ext_base = REG_HMEBOX_EXT_0 + u16::from(boxnum) * 4;
            let mut ext = [0u8; 4];
            ext[..payload.len() - 3].copy_from_slice(&payload[3..]);
            for (i, b) in ext.iter().enumerate() {
                io.write8(ext_base + i as u16, *b)?;
            }
            content[1..4].copy_from_slice(&payload[..3]);
        } else {
            content[1..1 + payload.len()].copy_from_slice(payload);
        }
        for (i, b) in content.iter().enumerate() {
            io.write8(base + i as u16, *b)?;
        }
        self.h2c_next = (boxnum + 1) & 3;
        Ok(())
    }

    /// `rtl8723e_dm_bt_balance`: H2C `0x0c` with `[ms0, ms1, on]`; turning
    /// balance on clears `fw_coexist_all_off`; always records
    /// `balance_on`.
    pub async fn balance<I: Io>(
        &mut self,
        io: &I,
        on: bool,
        ms0: u8,
        ms1: u8,
    ) -> Result<(), Error> {
        self.h2c_fill(io, H2C_BALANCE, &[ms0, ms1, u8::from(on)])
            .await?;
        if on {
            self.fw_all_off = false;
        }
        self.balance_on = on;
        Ok(())
    }

    /// `rtl8723e_dm_bt_agc_table`: the five MMIO dwords for the ON/OFF
    /// table, all written to the `0xc78` port as in Linux, then the RF
    /// half (`RF_RX_AGC_HP` x4, `RF_RX_G1`) on `RF90_PATH_A` through
    /// `rtl8723_phy_rf_serial_write` (full `0xfffff` mask, so
    /// `rtl8723e_phy_set_rf_reg` does no read-modify-write).
    pub fn agc_table<I: Io>(&mut self, io: &I, on: bool) -> Result<(), Error> {
        let (table, rf) = if on {
            (AGC_TABLE_ON, AGC_RF_ON)
        } else {
            (AGC_TABLE_OFF, AGC_RF_OFF)
        };
        for dword in table {
            io.write32(REG_AGC_TABLE, dword)?;
        }
        for (reg, value) in rf {
            rf_serial_write(io, RfPath::A, reg, value)?;
        }
        self.agc_on = on;
        Ok(())
    }

    /// `rtl8723e_dm_bt_bb_back_off_level`: MMIO `0xc04`; turning it ON
    /// also clears `sw_coexist_all_off`.
    pub fn bb_back_off<I: Io>(&mut self, io: &I, on: bool) -> Result<(), Error> {
        io.write32(
            REG_BB_BACKOFF,
            if on { BB_BACKOFF_ON } else { BB_BACKOFF_OFF },
        )?;
        if on {
            self.sw_all_off = false;
        }
        self.backoff_on = on;
        Ok(())
    }

    /// The `rtl8723e_dm_bt_{fw,sw,hw}_coex_all_off` wrappers: idempotent
    /// (early return when already set), then set. The SW wrapper also
    /// runs its two grounded sub-commands (`agc_table` OFF,
    /// `bb_back_off` OFF). The full `_8723a` sequences (firmware
    /// 3a/TDMA/DAC-swing commands, coex-table + HW PTA mode, RF LPF
    /// corner, DAC swing, TX-rate-adapt penalty) live in `dm.rs`
    /// (`all_off_fw` / `all_off_sw` / `all_off_hw`); this wrapper keeps
    /// its flag bookkeeping and must not be read as hardware state.
    pub fn coex_all_off<I: Io>(&mut self, io: &I) -> Result<(), Error> {
        if !self.fw_all_off {
            self.fw_all_off = true;
        }
        if !self.sw_all_off {
            self.agc_table(io, false)?;
            self.bb_back_off(io, false)?;
            self.sw_all_off = true;
        }
        if !self.hw_all_off {
            self.hw_all_off = true;
        }
        Ok(())
    }

    /// `rtl8723e_dm_bt_is_coexist_state_changed`: previous `cstate` /
    /// `cstate_h` both equal to current → false, else true.
    pub fn is_coexist_state_changed(&self) -> bool {
        self.prev_cstate != self.cstate || self.prev_cstate_h != self.cstate_h
    }

    /// `rtl8723e_dm_bt_is_wifi_up_link`: `tx_busy_traffic`.
    pub fn is_wifi_up_link(&self) -> bool {
        self.tx_busy
    }
}
