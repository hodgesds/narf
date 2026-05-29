//! RTL8192EU chip-specific init.
//!
//! RTL8192EU: 802.11n 2×2 USB, dual spatial streams.
//! USB IDs: `0x0BDA:0x818B` (native), plus many OEM variants.
//! Firmware: `rtlwifi/rtl8192eufw.bin`.
//!
//! ## Stage 0/1 register init
//!
//! The 8192EU follows the same power-on pattern as 8192C-based parts.
//! Key differences vs 8188EU:
//! - 2 RF paths (A + B).
//! - Different TX page allocation (`TX_TOTAL_PAGE_NUM_8192E = 0xF3`).
//! - Separate LDO 1.2V control register (`REG_8192E_LDOV12_CTRL`).
//!
//! Source: `8192e.c::rtl8192eu_power_on` and `rtl8xxxu_gen2_power_on`.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/8192e.c`
//! - `drivers/net/wireless/realtek/rtl8xxxu/regs.h`

#![allow(dead_code)]

use super::regs::*;
use super::usb::UsbControlSetup;

/// Chip name string.
pub const CHIP_NAME: &str = "RTL8192EU";

/// Firmware blob path.
pub const FIRMWARE_NAME: &str = "rtlwifi/rtl8192eufw.bin";

/// TX total pages. `TX_TOTAL_PAGE_NUM_8192E = 0xF3`.
pub const TX_TOTAL_PAGES: u8 = TX_TOTAL_PAGE_NUM_8192E;

/// TX high-priority page count. `TX_PAGE_NUM_HI_PQ_8192E = 0x08`.
pub const TX_PAGE_NUM_HI: u8 = 0x08;
/// TX low-priority page count. `TX_PAGE_NUM_LO_PQ_8192E = 0x0C`.
pub const TX_PAGE_NUM_LO: u8 = 0x0C;
/// TX normal-priority page count. `TX_PAGE_NUM_NORM_PQ_8192E = 0x00`.
pub const TX_PAGE_NUM_NORM: u8 = 0x00;

/// TX descriptor size: 32 bytes.
pub const TX_DESC_SIZE: usize = TXDESC_SIZE_32;

/// LDO 1.2V control register.
/// `REG_8192E_LDOV12_CTRL = 0x0014`. `regs.h` L70.
pub const REG_8192E_LDOV12_CTRL: u16 = 0x0014;
/// LDO 1.2V enable bit (bit 0 of `REG_8192E_LDOV12_CTRL`).
pub const LDOV12_ENABLE: u8 = 0x01;

/// Stage 0 / 1 register init table for RTL8192EU.
///
/// Sequence: assert LDO 1.2V, enable MAC via APS_FSMCO, open CR.
///
/// Source: derived from `8192e.c` power-on sequence and `8192c.c`
/// gen1 reference (8192EU uses the gen2 path but the LDO step is common).
pub const INIT_TABLE: &[(u16, u8)] = &[
    // Enable LDO 1.2V.
    (REG_8192E_LDOV12_CTRL, LDOV12_ENABLE),
    // MAC enable via APS_FSMCO byte 1.
    (REG_APS_FSMCO as u16 + 1, 0x08),
    // CR open (two bytes).
    (REG_CR, (CR_OPEN_8188E & 0xFF) as u8),
    (REG_CR + 1, ((CR_OPEN_8188E >> 8) & 0xFF) as u8),
];

/// Chip-init stage-0 register bank.
pub fn stage0_register_bank() -> &'static [(u16, u8)] {
    INIT_TABLE
}

/// Build USB control-transfer setup for LDO enable.
pub fn ldo12_enable_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_8192E_LDOV12_CTRL, 1)
}

/// Build USB control-transfer setups for CR open (lo + hi byte).
pub fn cr_open_setups() -> [UsbControlSetup; 2] {
    [
        UsbControlSetup::write(REG_CR, 1),
        UsbControlSetup::write(REG_CR + 1, 1),
    ]
}
