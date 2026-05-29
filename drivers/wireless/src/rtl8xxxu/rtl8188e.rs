//! RTL8188EU chip-specific init.
//!
//! RTL8188EU: 802.11n 1×1 USB, single spatial stream.
//! USB IDs: `0x0BDA:0x8179` (native), `0x0BDA:0x0179` (TV variant).
//! Firmware: `rtlwifi/rtl8188eufw.bin`.
//!
//! ## Stage 0/1 register init
//!
//! The minimal bring-up sequence (`rtl8188eu_power_on` in Linux
//! `8188e.c`, ~L1165) for the 8188EU after USB enumeration:
//!
//! 1. Write `APS_FSMCO_MAC_ENABLE (BIT8)` to `REG_APS_FSMCO` to
//!    power the MAC block.
//! 2. Write CR_OPEN_8188E to `REG_CR`.
//!
//! Full PHY / RF init is deferred.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/8188e.c`:
//!   `rtl8188eu_power_on` (~L1165..L1200),
//!   `rtl8188eu_fops` (~L1839).

#![allow(dead_code)]

use super::regs::*;
use super::usb::UsbControlSetup;

/// Per-chip register initialisation table for the RTL8188EU.
///
/// Each entry is `(address, value)` representing a write-8 to the
/// given register offset via USB control transfer. The sequence
/// mirrors the cross-part prologue written by `rtl8188eu_power_on`
/// before the PHY tables are loaded.
///
/// Source: `8188e.c::rtl8188eu_power_on` ~L1165..L1200.
pub const INIT_TABLE: &[(u16, u8)] = &[
    // Step 1: APS_FSMCO — MAC_ENABLE. Written as a 32-bit write in
    // Linux; we write byte 1 (offset APS_FSMCO+1) which contains
    // BIT0 of the byte corresponding to APS_FSMCO_MAC_ENABLE.
    // The 8188eu_power_on helper functions handle the full sequence;
    // here we capture the essence as a (reg, val8) table.
    (REG_APS_FSMCO as u16 + 1, 0x08), // APS_FSMCO_MAC_ENABLE = BIT(8) → byte 1 = 0x08
    // Step 2: CR open mask (write as 16-bit via two byte writes).
    (REG_CR, (CR_OPEN_8188E & 0xFF) as u8),
    (REG_CR + 1, ((CR_OPEN_8188E >> 8) & 0xFF) as u8),
];

/// Chip name string for this family.
pub const CHIP_NAME: &str = "RTL8188EU";

/// Firmware blob path.
pub const FIRMWARE_NAME: &str = "rtlwifi/rtl8188eufw.bin";

/// TX total page count for 8188EU.
/// Source: `rtl8xxxu.h::TX_TOTAL_PAGE_NUM_8188E = 0xA9`.
pub const TX_TOTAL_PAGES: u8 = TX_TOTAL_PAGE_NUM_8188E;

/// TX high-priority page count.
/// `TX_PAGE_NUM_HI_PQ_8188E = 0x29`.
pub const TX_PAGE_NUM_HI: u8 = 0x29;
/// TX low-priority page count.
/// `TX_PAGE_NUM_LO_PQ_8188E = 0x1C`.
pub const TX_PAGE_NUM_LO: u8 = 0x1C;
/// TX normal-priority page count.
/// `TX_PAGE_NUM_NORM_PQ_8188E = 0x1C`.
pub const TX_PAGE_NUM_NORM: u8 = 0x1C;

/// TX descriptor size: 32 bytes.
pub const TX_DESC_SIZE: usize = TXDESC_SIZE_32;

/// Max secure CAM entries.
/// `rtl8188eu_fops.max_sec_cam_num = 32`.
pub const MAX_SEC_CAM: usize = 32;

/// Build the USB control-transfer setup for the APS_FSMCO write
/// (byte 1 of the register — enables MAC_ENABLE).
pub fn aps_fsmco_mac_enable_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_APS_FSMCO as u16 + 1, 1)
}

/// Build the USB control-transfer setups for the CR_OPEN_8188E write
/// (two byte writes: low byte, then high byte).
pub fn cr_open_setups() -> [UsbControlSetup; 2] {
    [
        UsbControlSetup::write(REG_CR, 1),
        UsbControlSetup::write(REG_CR + 1, 1),
    ]
}

/// Chip-init stage-0 register bank: returns `(address, value)` pairs
/// for all USB write-1 transactions in the Stage 0 / 1 prologue.
///
/// Callers iterate this slice and issue `usb_write8(addr, val)` for
/// each entry.
pub fn stage0_register_bank() -> &'static [(u16, u8)] {
    INIT_TABLE
}
