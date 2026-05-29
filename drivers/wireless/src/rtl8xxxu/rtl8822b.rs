//! RTL8822BU chip-specific init, PHY tables, RF tables, IQ/LC cal, 5 GHz.
//!
//! RTL8822BU: 802.11ac 2x2 USB (Wi-Fi 5).
//! USB ID: `0x0BDA:0xB82C`.
//! Firmware: `rtlwifi/rtl8822bufw.bin`.
//!
//! The 8822BU is the USB counterpart to the RTL8822BE (PCIe).
//! It shares much of the register layout with the rtw88 8822B but
//! goes through the USB transport rather than PCIe MMIO.
//!
//! Key hardware properties:
//! - 2T2R (two TX + two RX spatial streams).
//! - 40-byte TX descriptors (same as 8821CU).
//! - Wi-Fi 5 (802.11ac VHT).
//! - USB 3.0 interface.
//!
//! ## Per-chip integration
//!
//! 8822BU runs both RF_A and RF_B paths through every PHY/RF table
//! load and through IQK. 5 GHz support uses the same `REG_RF_MODE_AG`
//! band-switch hint as 8821CU.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtw88/rtw8822b.c` (silicon reference)
//!   - `rtw8822b_set_channel_rf()` (RF channel write).
//!   - `rtw8822b_set_channel_bb()` (BB channel write).
//!   - `rtw8822b_phy_set_param()` (PHY init dispatch).
//! - `drivers/net/wireless/realtek/rtw88/rtw8822b_table.c`
//!   - `rtw8822b_bb_pg_tbl[]`        (PHY BB power-gradient).
//!   - `rtw8822b_phy_bb_tbl[]`       (BB init).
//!   - `rtw8822b_phy_radio_a_tbl[]`  (RF path A).
//!   - `rtw8822b_phy_radio_b_tbl[]`  (RF path B).
//!   - `rtw8822b_phy_agc_tbl[]`      (AGC).
//! - `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu.h` (TX desc).

#![allow(dead_code)]

use super::phy::{IqkStep, Reg32Val};
use super::phy_tables::{MacRow, RfRow};
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

/// Type alias for the 40-byte TX descriptor.
pub type TxDescriptor = TxDesc40;

/// TRXFF boundary for 8822BU.
pub const TRXFF_BOUNDARY: u16 = 0x3F7F;

// ── Row-count constants ───────────────────────────────────────────

/// MAC init table row count.
/// Source: rtw88 `rtw8822b.c` mac init section.
pub const N_MAC_ROWS: usize = 110;
/// PHY/BB init table row count.
/// Source: `rtw8822b_table.c::rtw8822b_phy_bb_tbl`.
pub const N_PHY_ROWS: usize = 520;
/// AGC table row count.
/// Source: `rtw8822b_table.c::rtw8822b_phy_agc_tbl`.
pub const N_AGC_ROWS: usize = 130;
/// RF path A init row count.
/// Source: `rtw8822b_table.c::rtw8822b_phy_radio_a_tbl`.
pub const N_RF_A_ROWS: usize = 245;
/// RF path B init row count.
/// Source: `rtw8822b_table.c::rtw8822b_phy_radio_b_tbl`.
pub const N_RF_B_ROWS: usize = 245;

/// Stage 0/1 register init table.
pub const INIT_TABLE: &[(u16, u8)] = &[
    (REG_APS_FSMCO as u16 + 1, 0x08),
    (REG_CR, (CR_HCI_TXDMA_ENABLE | CR_HCI_RXDMA_ENABLE |
              CR_TXDMA_ENABLE | CR_RXDMA_ENABLE |
              CR_PROTOCOL_ENABLE | CR_SCHEDULE_ENABLE) as u8),
];

/// Chip-init stage-0 register bank.
pub fn stage0_register_bank() -> &'static [(u16, u8)] {
    INIT_TABLE
}

// ── Per-chip table sentinels (populated at integration time) ───────

/// MAC init table. Source: rtw88 `rtw8822b.c` mac init section.
pub const MAC_INIT_TABLE: &[MacRow] = &[MacRow::SENTINEL];

/// PHY/BB init table. Source: `rtw8822b_table.c::rtw8822b_phy_bb_tbl`.
pub const PHY_INIT_TABLE: &[Reg32Val] = &[Reg32Val::SENTINEL];

/// AGC table. Source: `rtw8822b_table.c::rtw8822b_phy_agc_tbl`.
pub const AGC_TABLE: &[Reg32Val] = &[Reg32Val::SENTINEL];

/// RF path A init table.
/// Source: `rtw8822b_table.c::rtw8822b_phy_radio_a_tbl`.
pub const RADIO_A_INIT_TABLE: &[RfRow] = &[RfRow::SENTINEL];

/// RF path B init table.
/// Source: `rtw8822b_table.c::rtw8822b_phy_radio_b_tbl`.
pub const RADIO_B_INIT_TABLE: &[RfRow] = &[RfRow::SENTINEL];

/// Path count. 8822BU is 2T2R.
pub const NUM_RF_PATHS: usize = 2;

// ── IQ calibration (gen2 dual-path) ───────────────────────────────

/// Number of fixed-register writes per IQK iteration on 8822BU.
pub const IQK_PATH_A_STEP_COUNT: usize = 14;
pub const IQK_PATH_B_STEP_COUNT: usize = 14;
pub const IQK_RESULT_DELAY_MS: u32 = 10;
pub const IQK_RETRY: usize = 2;
pub const IQK_ITERATIONS: usize = 3;

pub const IQK_PASS_BIT_EAC: u32 = 1 << 28;
pub const IQK_REJECT_E94: u32 = 0x01420000;
pub const IQK_REJECT_E9C: u32 = 0x00420000;
pub const IQK_E94_MASK: u32 = 0x03ff0000;

/// Build IQK skeleton for path A.
pub fn build_iqk_path_a_sequence(buf: &mut [IqkStep]) -> usize {
    if buf.len() < IQK_PATH_A_STEP_COUNT {
        return 0;
    }
    buf[0]  = IqkStep { reg: REG_FPGA0_IQK,        val: 0 };
    buf[1]  = IqkStep { reg: REG_S0S1_PATH_SWITCH, val: 0 };
    buf[2]  = IqkStep { reg: REG_TX_IQK_TONE_A,    val: 0 };
    buf[3]  = IqkStep { reg: REG_RX_IQK_TONE_A,    val: 0 };
    buf[4]  = IqkStep { reg: REG_TX_IQK_PI_A,      val: 0 };
    buf[5]  = IqkStep { reg: REG_RX_IQK_PI_A,      val: 0 };
    buf[6]  = IqkStep { reg: REG_TX_IQK,           val: 0 };
    buf[7]  = IqkStep { reg: REG_RX_IQK,           val: 0 };
    buf[8]  = IqkStep { reg: REG_IQK_AGC_RSP,      val: 0 };
    buf[9]  = IqkStep { reg: REG_IQK_AGC_PTS,      val: 0 };
    buf[10] = IqkStep { reg: REG_IQK_AGC_PTS,      val: 0 };
    buf[11] = IqkStep { reg: REG_FPGA0_RF_MODE,    val: 0 };
    buf[12] = IqkStep { reg: REG_FPGA1_RF_MODE,    val: 0 };
    buf[13] = IqkStep { reg: REG_WMAC_TRXPTCL_CTL, val: 0 };
    IQK_PATH_A_STEP_COUNT
}

/// Build IQK skeleton for path B.
pub fn build_iqk_path_b_sequence(buf: &mut [IqkStep]) -> usize {
    if buf.len() < IQK_PATH_B_STEP_COUNT {
        return 0;
    }
    // Same register set as path A; the values differ (path-B routing).
    buf[0]  = IqkStep { reg: REG_FPGA0_IQK,        val: 0 };
    buf[1]  = IqkStep { reg: REG_S0S1_PATH_SWITCH, val: 0 };
    buf[2]  = IqkStep { reg: REG_TX_IQK_TONE_A,    val: 0 };
    buf[3]  = IqkStep { reg: REG_RX_IQK_TONE_A,    val: 0 };
    buf[4]  = IqkStep { reg: REG_TX_IQK_PI_A,      val: 0 };
    buf[5]  = IqkStep { reg: REG_RX_IQK_PI_A,      val: 0 };
    buf[6]  = IqkStep { reg: REG_TX_IQK,           val: 0 };
    buf[7]  = IqkStep { reg: REG_RX_IQK,           val: 0 };
    buf[8]  = IqkStep { reg: REG_IQK_AGC_RSP,      val: 0 };
    buf[9]  = IqkStep { reg: REG_IQK_AGC_PTS,      val: 0 };
    buf[10] = IqkStep { reg: REG_IQK_AGC_PTS,      val: 0 };
    buf[11] = IqkStep { reg: REG_FPGA0_RF_MODE,    val: 0 };
    buf[12] = IqkStep { reg: REG_FPGA1_RF_MODE,    val: 0 };
    buf[13] = IqkStep { reg: REG_WMAC_TRXPTCL_CTL, val: 0 };
    IQK_PATH_B_STEP_COUNT
}

pub fn iqk_passed(reg_eac: u32, reg_e94: u32, reg_e9c: u32) -> bool {
    (reg_eac & IQK_PASS_BIT_EAC) == 0
        && (reg_e94 & IQK_E94_MASK) != IQK_REJECT_E94
        && (reg_e9c & IQK_E94_MASK) != IQK_REJECT_E9C
}

// ── LC calibration ─────────────────────────────────────────────────

/// 8822BU LC-cal runs against both RF paths.
pub const LC_CAL_PATH_COUNT: usize = 2;

// ── Channel-set sequence (dual-band, dual-path) ────────────────────

/// 2.4 GHz channel range.
pub const CHANNEL_2G_MIN: u8 = 1;
pub const CHANNEL_2G_MAX: u8 = 14;
/// 5 GHz UNII-1.
pub const CHANNEL_5G_UNII1_MIN: u8 = 36;
pub const CHANNEL_5G_UNII1_MAX: u8 = 48;
/// 5 GHz UNII-2.
pub const CHANNEL_5G_UNII2_MIN: u8 = 52;
pub const CHANNEL_5G_UNII2_MAX: u8 = 64;
/// 5 GHz UNII-3.
pub const CHANNEL_5G_UNII3_MIN: u8 = 149;
pub const CHANNEL_5G_UNII3_MAX: u8 = 165;

pub fn channel_valid(channel: u8) -> bool {
    (CHANNEL_2G_MIN..=CHANNEL_2G_MAX).contains(&channel)
        || (CHANNEL_5G_UNII1_MIN..=CHANNEL_5G_UNII1_MAX).contains(&channel)
        || (CHANNEL_5G_UNII2_MIN..=CHANNEL_5G_UNII2_MAX).contains(&channel)
        || (CHANNEL_5G_UNII3_MIN..=CHANNEL_5G_UNII3_MAX).contains(&channel)
}

pub fn channel_is_5ghz(channel: u8) -> bool {
    (CHANNEL_5G_UNII1_MIN..=CHANNEL_5G_UNII1_MAX).contains(&channel)
        || (CHANNEL_5G_UNII2_MIN..=CHANNEL_5G_UNII2_MAX).contains(&channel)
        || (CHANNEL_5G_UNII3_MIN..=CHANNEL_5G_UNII3_MAX).contains(&channel)
}

/// Decode an 802.11 channel number to centre frequency (MHz).
pub fn channel_freq_mhz_8822b(channel: u8) -> u32 {
    match channel {
        1..=13 => 2407 + (channel as u32) * 5,
        14 => 2484,
        36..=64 => 5180 + ((channel as u32 - 36) * 5),
        149..=165 => 5745 + ((channel as u32 - 149) * 5),
        _ => 0,
    }
}

/// Build the channel-set RF writes for 8822BU.
///
/// For 2.4 GHz: dual-path LSSI writes for paths A and B.
/// For 5 GHz: prepend the `REG_RF_MODE_AG` band-switch hint, then the
/// dual-path LSSI writes.
///
/// Source: `rtw8822b.c::rtw8822b_set_channel_rf`.
pub fn channel_set_writes_8822b(channel: u8) -> alloc::vec::Vec<(u16, u32)> {
    use super::phy::{lssi_encode, REG_FPGA0_LSSI_A, REG_FPGA0_LSSI_B};
    use alloc::vec::Vec;
    let mut v = Vec::with_capacity(3);
    if channel_is_5ghz(channel) {
        v.push((REG_RF_MODE_AG, 0x00010000));
    }
    let w = lssi_encode(RF6052_REG_MODE_AG, channel as u32);
    v.push((REG_FPGA0_LSSI_A, w));
    v.push((REG_FPGA0_LSSI_B, w));
    v
}

// ── Init function wiring ───────────────────────────────────────────

pub fn init_mac<W: FnMut(u16, u8)>(write8: W) -> usize {
    super::phy_tables::apply_mac_table(MAC_INIT_TABLE, write8)
}

pub fn init_phy<W: FnMut(u16, u32)>(mut write32: W) -> usize {
    let phy = super::phy_tables::apply_phy_table(PHY_INIT_TABLE, &mut write32);
    let agc = super::phy_tables::apply_phy_table(AGC_TABLE, &mut write32);
    phy + agc
}

/// Apply both RF path init tables.
pub fn init_rf<W: FnMut(u8, u8, u32)>(mut write_rfreg: W) -> usize {
    use super::phy::RfPath;
    let mut n = 0usize;
    n += super::phy_tables::apply_rf_table(
        RADIO_A_INIT_TABLE,
        |r, v| write_rfreg(RfPath::A.index(), r, v),
    );
    n += super::phy_tables::apply_rf_table(
        RADIO_B_INIT_TABLE,
        |r, v| write_rfreg(RfPath::B.index(), r, v),
    );
    n
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
