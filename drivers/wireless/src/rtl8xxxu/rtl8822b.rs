//! RTL8822BU chip-specific init.
//!
//! RTL8822BU: 802.11ac 2×2 USB (Wi-Fi 5).
//! USB ID: `0x0BDA:0xB82C`.
//! Firmware: `rtlwifi/rtl8822bufw.bin`.
//!
//! The 8822BU is the USB counterpart to the RTL8822BE (PCIe).
//! It shares much of the register layout with the RTW88 8822B but
//! goes through the USB transport rather than PCIE MMIO.
//!
//! Key hardware properties:
//! - 2T2R (two TX + two RX spatial streams).
//! - 40-byte TX descriptors (same as 8821CU).
//! - Wi-Fi 5 (802.11ac VHT).
//! - USB 3.0 interface.
//!
//! ## Stage 0/1 register init
//!
//! The 8822BU bring-up shares most steps with 8822BE (PCIe) from
//! RTW88, adapted for the USB control-transfer path.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtw88/rtw8822b.c` (PCIe reference)
//! - `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu.h`

#![allow(dead_code)]

use super::regs::*;
pub use super::rtl8821c::TxDesc40;
use super::usb::UsbControlSetup;

/// Chip name string.
pub const CHIP_NAME: &str = "RTL8822BU";

/// Firmware blob path.
pub const FIRMWARE_NAME: &str = "rtlwifi/rtl8822bufw.bin";

/// TX total pages: default (0xF8).
pub const TX_TOTAL_PAGES: u8 = TX_TOTAL_PAGE_NUM_DEFAULT;

/// TX descriptor size: 40 bytes (shared with 8821CU).
pub const TX_DESC_SIZE: usize = TXDESC_SIZE_40;

/// Type alias for the 40-byte TX descriptor; 8822BU uses the same layout.
pub type TxDescriptor = TxDesc40;

/// TRXFF boundary for 8822BU. Limits the RX FIFO buffer size to avoid
/// overlap with the TX aggregation area. Value derived from the RTW88
/// 8822B driver (same chip silicon, different bus interface).
pub const TRXFF_BOUNDARY: u16 = 0x3F7F;

/// Stage 0/1 register init table for RTL8822BU.
pub const INIT_TABLE: &[(u16, u8)] = &[
    // MAC enable via APS_FSMCO.
    (REG_APS_FSMCO as u16 + 1, 0x08),
    // CR open low byte.
    (REG_CR, (CR_HCI_TXDMA_ENABLE | CR_HCI_RXDMA_ENABLE |
              CR_TXDMA_ENABLE | CR_RXDMA_ENABLE |
              CR_PROTOCOL_ENABLE | CR_SCHEDULE_ENABLE) as u8),
];

/// Chip-init stage-0 register bank.
pub fn stage0_register_bank() -> &'static [(u16, u8)] {
    INIT_TABLE
}

/// Build USB control-transfer setup for APS_FSMCO MAC enable.
pub fn aps_fsmco_mac_enable_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_APS_FSMCO as u16 + 1, 1)
}

/// Build bulk-OUT TX frame with a 40-byte descriptor prefix.
pub fn build_bulk_out_frame_40(payload: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;
    let desc = TxDesc40::management(payload.len() as u16, 0);
    let desc_bytes = desc.to_bytes();
    let mut out = Vec::with_capacity(TxDesc40::SIZE + payload.len());
    out.extend_from_slice(&desc_bytes);
    out.extend_from_slice(payload);
    out
}

extern crate alloc;
