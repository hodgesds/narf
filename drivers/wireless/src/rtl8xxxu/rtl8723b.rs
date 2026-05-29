//! RTL8723BU chip-specific init.
//!
//! RTL8723BU: 802.11n 1×1 USB + Bluetooth combo.
//! USB IDs: `0x0BDA:0xB720` (native), `0x7392:0xA611` (rebranded).
//! Firmware: `rtlwifi/rtl8723bufw.bin`.
//!
//! The 8723B is a multi-function device (WiFi + BT share the USB
//! interface). The EFUSE contains two WiFi and two BT sub-maps; the
//! WiFi EFUSE is selected via `EFUSE_WIFI_SELECT` bits in
//! `REG_EFUSE_TEST`.
//!
//! Additionally, `REG_EFUSE_ACCESS` must be written with
//! `EFUSE_ACCESS_ENABLE (0x69)` before EFUSE reads on this chip
//! (unlike 8188EU where it is optional).
//!
//! ## Stage 0/1 register init
//!
//! The 8723BU power-on sequence (`rtl8723bu_power_on` in Linux
//! `8723b.c`) is similar to the 8723A but uses the gen2 path.
//! Key steps:
//! 1. Select WiFi EFUSE cell via `REG_EFUSE_TEST`.
//! 2. Write `EFUSE_ACCESS_ENABLE` to `REG_EFUSE_ACCESS`.
//! 3. Assert `APS_FSMCO_MAC_ENABLE` in `REG_APS_FSMCO`.
//! 4. Write CR_OPEN to `REG_CR`.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/8723b.c`
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c`
//!   `rtl8xxxu_read_efuse` ~L1795 (multi-func EFUSE select).

#![allow(dead_code)]

use super::regs::*;
use super::usb::UsbControlSetup;

/// Chip name string.
pub const CHIP_NAME: &str = "RTL8723BU";

/// Firmware blob path.
pub const FIRMWARE_NAME: &str = "rtlwifi/rtl8723bufw.bin";

/// TX total pages. `TX_TOTAL_PAGE_NUM_8723B = 0xF7`.
pub const TX_TOTAL_PAGES: u8 = TX_TOTAL_PAGE_NUM_8723B;

/// TX high-priority page count. `TX_PAGE_NUM_HI_PQ_8723B = 0x0C`.
pub const TX_PAGE_NUM_HI: u8 = 0x0C;
/// TX low-priority page count. `TX_PAGE_NUM_LO_PQ_8723B = 0x02`.
pub const TX_PAGE_NUM_LO: u8 = 0x02;
/// TX normal-priority page count. `TX_PAGE_NUM_NORM_PQ_8723B = 0x02`.
pub const TX_PAGE_NUM_NORM: u8 = 0x02;

/// TX descriptor size: 32 bytes.
pub const TX_DESC_SIZE: usize = TXDESC_SIZE_32;

/// Number of channel groups for 8723B RF calibration.
/// `RTL8723B_CHANNEL_GROUPS = 6`. `rtl8xxxu.h` ~L83.
pub const CHANNEL_GROUPS: usize = 6;
/// Maximum RF paths on 8723B.
/// `RTL8723B_TX_COUNT = 4`. `rtl8xxxu.h` ~L84.
pub const TX_COUNT: usize = 4;
/// Maximum RF paths.
/// `RTL8723B_MAX_RF_PATHS = 4`. `rtl8xxxu.h` ~L85.
pub const MAX_RF_PATHS: usize = 4;

/// Stage 0 / 1 register init table for RTL8723BU.
///
/// Multi-function EFUSE cell selection is done separately in the EFUSE
/// preamble path; this table covers the MAC bring-up portion.
///
/// Source: `8723b.c::rtl8723bu_power_on` prologue.
pub const INIT_TABLE: &[(u16, u8)] = &[
    // Assert EFUSE access enable (required for 8723 family).
    (REG_EFUSE_ACCESS, EFUSE_ACCESS_ENABLE),
    // MAC enable.
    (REG_APS_FSMCO as u16 + 1, 0x08),
    // CR open.
    (REG_CR, (CR_OPEN_8188E & 0xFF) as u8),
    (REG_CR + 1, ((CR_OPEN_8188E >> 8) & 0xFF) as u8),
];

/// Chip-init stage-0 register bank.
pub fn stage0_register_bank() -> &'static [(u16, u8)] {
    INIT_TABLE
}

/// Build USB control-transfer setup to select the WiFi EFUSE cell.
///
/// Writes `EFUSE_WIFI_SELECT` into bits[9:8] of `REG_EFUSE_TEST`.
/// The caller is expected to read-modify-write the full 32-bit value.
pub fn efuse_wifi_select_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_EFUSE_TEST, 4)
}

/// Apply `EFUSE_WIFI_SELECT` to an existing `REG_EFUSE_TEST` value.
pub fn apply_efuse_wifi_select(existing: u32) -> u32 {
    (existing & !EFUSE_SELECT_MASK) | EFUSE_WIFI_SELECT
}
