//! rtlwifi Bluetooth coexistence — applicable to 8723AE, 8723BE,
//! 8821AE (combo Wi-Fi + BT silicon).
//!
//! The combo chips share their RF front-end between Wi-Fi and BT.
//! Coexistence is implemented as a state-machine that pushes one of
//! a small set of "BT-TDMA" patterns into the chip via an H2C command;
//! the chip's MCU then time-slices the antenna.
//!
//! NARF carries the *decision matrix* (Wi-Fi state × BT state →
//! TDMA-pattern selector) plus the H2C encoding.  The actual table of
//! TDMA slot bytes is per-chip and lives in Linux's
//! `btcoexist/halbtc8723b2ant.c` (etc.) — for bring-up we emit the
//! "BT-only" / "Wi-Fi-only" extremes and the "shared antenna 50/50"
//! middle pattern.
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/btcoexist/halbtc8723b2ant.c::halbtc8723b2ant_action_*`
//! - `rtl8723be/hw.c::rtl8723be_dm_init_dynamic_atc_switch` (BT-coex
//!   init at probe time)
//! - `rtl8821ae/btc.c::rtl8821ae_btc_init` — 8821AE wraps the same
//!   coexist core

#![allow(dead_code)]

use super::h2c::{send_h2c, H2cError, H2cState};
use super::regs::*;
use narf_bus::MmioRegion;

/// True for chips that ship a BT radio (combo silicon).
pub const fn has_bt(did: u16) -> bool {
    matches!(did, RTL_DEV_8723AE | RTL_DEV_8723BE | RTL_DEV_8821AE)
}

/// One slot in the BT-coex decision matrix.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WifiState {
    /// No association — Wi-Fi can yield freely.
    Idle,
    /// Connected, transferring data.
    Connected,
    /// Active scan in progress.
    Scanning,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BtState {
    /// BT off or no link.
    Idle,
    /// BT-only (A2DP / SCO call active, no Wi-Fi traffic expected).
    Streaming,
    /// BT inquiry / page (transient).
    Inquiry,
}

/// One TDMA pattern.  In production this maps to one row of the
/// per-chip TDMA byte table; here we encode the gross policy.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TdmaPattern {
    /// Wi-Fi-only: BT yields entirely.
    WifiOnly,
    /// BT-only: Wi-Fi yields entirely.
    BtOnly,
    /// 50/50 shared antenna.
    Shared,
}

/// Pick a TDMA pattern for the (wifi, bt) state pair.  Tracks the
/// Linux `halbtc8723b2ant_action_*` policy at coarse granularity.
pub const fn pattern_for(wifi: WifiState, bt: BtState) -> TdmaPattern {
    match (wifi, bt) {
        (WifiState::Idle, BtState::Streaming) => TdmaPattern::BtOnly,
        (WifiState::Idle, BtState::Inquiry) => TdmaPattern::BtOnly,
        (WifiState::Idle, BtState::Idle) => TdmaPattern::WifiOnly,
        (WifiState::Connected, BtState::Idle) => TdmaPattern::WifiOnly,
        (WifiState::Connected, BtState::Streaming) => TdmaPattern::Shared,
        (WifiState::Connected, BtState::Inquiry) => TdmaPattern::Shared,
        (WifiState::Scanning, _) => TdmaPattern::Shared,
    }
}

/// H2C element-id for BT coexistence commands on 8723BE / 8821AE.
/// Source: `rtl8723be/fw.h::H2C_8723B_B_TYPE_TDMA`.
pub const H2C_BT_TDMA: u8 = 0x66;

/// Encode a TDMA pattern as a 5-byte H2C payload (Linux: `tdma_byte[5]`).
pub const fn encode_tdma(pattern: TdmaPattern) -> [u8; 5] {
    match pattern {
        TdmaPattern::WifiOnly => [0x00, 0x00, 0x00, 0x00, 0x00],
        TdmaPattern::BtOnly => [0x61, 0x00, 0x00, 0x00, 0x00],
        TdmaPattern::Shared => [0xE3, 0x12, 0x03, 0x10, 0x90],
    }
}

/// Push a TDMA pattern into the chip via H2C.
///
/// # Safety
/// Caller must own BAR0 exclusively, firmware loaded + ready.
pub unsafe fn apply_pattern(
    mmio: &MmioRegion,
    state: &mut H2cState,
    pattern: TdmaPattern,
) -> Result<u8, H2cError> {
    let payload = encode_tdma(pattern);
    // SAFETY: caller-asserted.
    unsafe { send_h2c(mmio, state, H2C_BT_TDMA, &payload) }
}

/// Initial BT-coex programming at probe time.  Mirrors the
/// `_initiate_btcoex` block in `rtl8723be/hw.c::_rtl8723be_hw_init`.
/// Sets up the default "idle" pattern so the chip's MCU has a sane
/// starting point.
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn init_btcoex(
    mmio: &MmioRegion,
    state: &mut H2cState,
    did: u16,
) -> Result<(), H2cError> {
    if !has_bt(did) {
        return Ok(());
    }
    let init = pattern_for(WifiState::Idle, BtState::Idle);
    // SAFETY: forwarded.
    unsafe {
        apply_pattern(mmio, state, init)?;
    }
    Ok(())
}
