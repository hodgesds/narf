//! RTL8723BU Bluetooth/WiFi coexistence algorithm.
//!
//! The 8723B is a WiFi+BT combo SoC sharing a single 2.4 GHz antenna.
//! The driver must arbitrate access to the medium between the WiFi MAC
//! and the BT controller (which runs its own firmware on the same die).
//!
//! Arbitration is done by sending H2C commands to the WiFi MCU which
//! programs the BT-controller's PTA (packet-traffic-arbiter) timing.
//! The classic table is "BT busy + WiFi connected" → use TDMA mode
//! with a 70:30 BT:WiFi split.
//!
//! ## Decision matrix
//!
//! | BT status        | WiFi status      | Action             | Command  |
//! |------------------|------------------|--------------------|----------|
//! | Off              | Connected        | wlan-only          | 0x62, 1  |
//! | Idle             | Connected        | wlan-only          | 0x62, 1  |
//! | Inquiry/page     | Connected        | TDMA 50/50         | 0x60, 50 |
//! | Connected (ACL)  | Connected        | TDMA 30/70 (BT 30%)| 0x60, 30 |
//! | Connected (eSCO) | Connected        | TDMA 70/30 (BT 70%)| 0x60, 70 |
//! | Off              | Scan             | wlan-only          | 0x62, 1  |
//! | Connected        | Scan             | TDMA 20/80         | 0x60, 20 |
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/8723b.c`
//!   - BT-coex H2C: ~L900-1000 (`rtl8723bu_update_bt_link_info`).
//! - Realtek "BTCoex" algorithm whitepaper (8723B variant).

#![allow(dead_code)]

use super::regs::{H2C_BT_INFO, H2C_BT_SET_MODE, H2C_BT_TDMA, H2C_BT_WLAN_ONLY};

/// BT controller's reported state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BtState {
    /// BT radio powered off.
    Off,
    /// BT radio on but idle (no link).
    Idle,
    /// BT performing inquiry / page scan.
    InquiryOrPage,
    /// BT in ACL data link (e.g. A2DP, headset).
    Acl,
    /// BT in synchronous link (eSCO/SCO, voice).
    Esco,
}

/// WiFi MAC state from the kernel side.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WifiState {
    Disconnected,
    Connected,
    Scanning,
}

/// Coex decision — what command to send to the WiFi MCU.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CoexDecision {
    /// H2C command byte.
    pub h2c_cmd: u8,
    /// First param byte (TDMA percentage or mode value).
    pub param: u8,
}

impl CoexDecision {
    /// WLAN-only mode: tell the BT controller to back off entirely.
    pub const WLAN_ONLY: Self = Self { h2c_cmd: H2C_BT_WLAN_ONLY, param: 1 };

    /// TDMA with given BT-percentage of the airtime budget.
    pub const fn tdma(bt_percent: u8) -> Self {
        Self { h2c_cmd: H2C_BT_TDMA, param: bt_percent }
    }
}

/// Compute the coex decision for the given `(bt, wifi)` state pair.
///
/// Implements the matrix above; the constants are conservative for
/// real-world operation rather than chasing maximum WiFi throughput.
pub fn coex_decision(bt: BtState, wifi: WifiState) -> CoexDecision {
    match (bt, wifi) {
        (BtState::Off | BtState::Idle, _) => CoexDecision::WLAN_ONLY,
        (_, WifiState::Disconnected) => CoexDecision::tdma(80), // give BT
        (BtState::InquiryOrPage, _) => CoexDecision::tdma(50),
        (BtState::Acl, WifiState::Connected) => CoexDecision::tdma(30),
        (BtState::Esco, WifiState::Connected) => CoexDecision::tdma(70),
        (BtState::Acl | BtState::Esco, WifiState::Scanning) => CoexDecision::tdma(20),
    }
}

/// Build the full H2C command payload (1 cmd byte + up to 7 param bytes).
///
/// Format matches `8723b.c::rtl8723bu_fill_h2c_cmd`: byte 0 = cmd,
/// bytes 1..n = parameters.
pub fn build_h2c(decision: CoexDecision) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0] = decision.h2c_cmd;
    buf[1] = decision.param;
    buf
}

/// Update BT-info H2C command after receiving a C2H event with a new
/// BT state report. The kernel uses this to refresh the coex tables.
pub fn build_bt_info_h2c(bt_link_count: u8, bt_busy: bool) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0] = H2C_BT_INFO;
    buf[1] = bt_link_count;
    buf[2] = if bt_busy { 1 } else { 0 };
    buf
}

/// Set-mode H2C: tells the WiFi MCU which coex algorithm version to use.
pub fn build_set_mode_h2c(mode: u8) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0] = H2C_BT_SET_MODE;
    buf[1] = mode;
    buf
}
