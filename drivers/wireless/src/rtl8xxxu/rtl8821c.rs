//! RTL8821CU chip-specific init.
//!
//! RTL8821CU: 802.11ac 1×1 USB (Wi-Fi 5).
//! USB ID: `0x0BDA:0xC811`.
//! Firmware: `rtlwifi/rtl8821cufw.bin`.
//!
//! The 8821CU uses 40-byte TX descriptors and belongs to the
//! second-generation register layout (no `EFUSE_ACCESS` byte needed).
//!
//! ## Stage 0/1 register init
//!
//! The RTL8821CU follows the gen2 power-on path similar to 8822B.
//! Specific register differences:
//! - 40-byte TX descriptor.
//! - Different TRXFF boundary.
//! - 1T1R RF configuration.
//!
//! Source: RTL8821CU USB support is in staging/rtl8821cu in the
//! kernel tree; for the canonical register sequence, the RTW88 8821C
//! implementation (`rtw88/rtw8821c.c`) is used as reference where the
//! USB variant shares init steps.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtw88/rtw8821c.c` (PCIe/USB reg init)
//! - `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu.h`

#![allow(dead_code)]

use super::regs::*;
use super::usb::UsbControlSetup;

/// Chip name string.
pub const CHIP_NAME: &str = "RTL8821CU";

/// Firmware blob path.
pub const FIRMWARE_NAME: &str = "rtlwifi/rtl8821cufw.bin";

/// TX total pages: default (0xF8).
pub const TX_TOTAL_PAGES: u8 = TX_TOTAL_PAGE_NUM_DEFAULT;

/// TX descriptor size: 40 bytes (second-generation descriptor).
pub const TX_DESC_SIZE: usize = TXDESC_SIZE_40;

/// 40-byte TX descriptor for 8821CU / 8822BU.
///
/// Source: `rtl8xxxu.h::rtl8xxxu_txdesc40` (10 × u32).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TxDesc40 {  // intentionally pub for 8822b re-export
    pub dw0: u32,
    pub dw1: u32,
    pub dw2: u32,
    pub dw3: u32,
    pub dw4: u32,
    pub dw5: u32,
    pub dw6: u32,
    pub dw7: u32,
    pub dw8: u32,
    pub dw9: u32,
}

impl TxDesc40 {
    pub const SIZE: usize = TXDESC_SIZE_40;

    /// Build a management TX descriptor.
    pub fn management(pkt_len: u16, qsel: u8) -> Self {
        let dw0 = (pkt_len as u32 & 0x1FFF) | (1u32 << 31);
        let dw1 = ((qsel as u32) << 8) & 0x1F00;
        Self {
            dw0,
            dw1,
            ..Default::default()
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        let words = [
            self.dw0, self.dw1, self.dw2, self.dw3, self.dw4,
            self.dw5, self.dw6, self.dw7, self.dw8, self.dw9,
        ];
        for (i, w) in words.iter().enumerate() {
            buf[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
        }
        buf
    }

    /// Extract packet length from DW0 bits[12:0].
    pub fn pkt_len(&self) -> u16 {
        (self.dw0 & 0x1FFF) as u16
    }
}

/// Stage 0/1 register init table for RTL8821CU.
pub const INIT_TABLE: &[(u16, u8)] = &[
    // MAC enable.
    (REG_APS_FSMCO as u16 + 1, 0x08),
    // CR open (lo byte only — no security/caltimer bits on 8821C).
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
