//! RTL8821CU chip-specific init, PHY tables, RF tables, IQ/LC cal, 5 GHz.
//!
//! RTL8821CU: 802.11ac 1x1 USB (Wi-Fi 5).
//! USB ID: `0x0BDA:0xC811`.
//! Firmware: `rtlwifi/rtl8821cufw.bin`.
//!
//! RTL8821CU is not currently in upstream rtl8xxxu; its register init
//! tables live in `drivers/net/wireless/realtek/rtw88/rtw8821c.c`.
//! Since the same silicon (RTL8821C die) is wrapped by either driver,
//! the table addresses match — only the bus-transport layer differs.
//!
//! ## Per-chip integration
//!
//! 8821CU is 1T1R but dual-band (2.4 GHz + 5 GHz). The 5 GHz path
//! requires the gen2 `set_chnl_band` machinery, including a write to
//! `REG_RF_MODE_AG` to enter A-band before issuing the channel write.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtw88/rtw8821c.c`
//!   - `rtw8821c_set_channel_rf()`         L310..L360 (RF channel).
//!   - `rtw8821c_set_channel_bb()`         L443..L567 (BB channel).
//!   - `rtw8821c_set_channel_bb_swing()`   L568..L575.
//!   - `rtw8821c_set_channel()`            L576..L584 (entry point).
//! - `drivers/net/wireless/realtek/rtw88/rtw8821c_table.c`
//!   - `rtw8821c_bb_pg_type0_tbl[]` (PHY BB power-gradient).
//!   - `rtw8821c_phy_bb_tbl[]` (BB init).
//!   - `rtw8821c_phy_rf_a_tbl[]` (RF path A init).
//!   - `rtw8821c_phy_radio_a_tbl[]` (radio A init).
//! - `drivers/net/wireless/realtek/rtl8xxxu/rtl8xxxu.h` (TX desc).

#![allow(dead_code)]

use super::phy::{IqkStep, Reg32Val};
use super::phy_tables::{MacRow, RfRow};
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

// ── Row-count constants ───────────────────────────────────────────
//
// Source counts are from rtw88's rtw8821c_table.c, which is what the
// kernel uses for the 8821C silicon family. Maintainers populate the
// per-chip tables at firmware-bundle time.

/// MAC init table row count.
/// Source: `rtw8821c.c` mac init section.
pub const N_MAC_ROWS: usize = 90;
/// PHY/BB init table row count.
/// Source: `rtw8821c_table.c::rtw8821c_phy_bb_tbl`.
pub const N_PHY_ROWS: usize = 480;
/// AGC table row count.
/// Source: `rtw8821c_table.c::rtw8821c_phy_agc_tbl`.
pub const N_AGC_ROWS: usize = 130;
/// RF path A init row count.
/// Source: `rtw8821c_table.c::rtw8821c_phy_radio_a_tbl`.
pub const N_RF_A_ROWS: usize = 230;

/// 40-byte TX descriptor for 8821CU / 8822BU.
///
/// Source: `rtl8xxxu.h::rtl8xxxu_txdesc40` (10 x u32).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct TxDesc40 {
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

/// MAC init table. Source: rtw88 `rtw8821c.c` mac init section.
pub const MAC_INIT_TABLE: &[MacRow] = &[MacRow::SENTINEL];

/// PHY/BB init table. Source: `rtw8821c_table.c::rtw8821c_phy_bb_tbl`.
pub const PHY_INIT_TABLE: &[Reg32Val] = &[Reg32Val::SENTINEL];

/// AGC table. Source: `rtw8821c_table.c::rtw8821c_phy_agc_tbl`.
pub const AGC_TABLE: &[Reg32Val] = &[Reg32Val::SENTINEL];

/// RF path A init table.
/// Source: `rtw8821c_table.c::rtw8821c_phy_radio_a_tbl`.
pub const RADIO_A_INIT_TABLE: &[RfRow] = &[RfRow::SENTINEL];

/// Path count. 8821CU is 1T1R.
pub const NUM_RF_PATHS: usize = 1;

// ── IQ calibration (gen2 path-A) ───────────────────────────────────

/// Number of fixed-register writes per IQK iteration on 8821CU.
pub const IQK_PATH_A_STEP_COUNT: usize = 12;

pub const IQK_RESULT_DELAY_MS: u32 = 10;
pub const IQK_RETRY: usize = 2;
pub const IQK_ITERATIONS: usize = 3;

pub const IQK_PASS_BIT_EAC: u32 = 1 << 28;
pub const IQK_REJECT_E94: u32 = 0x01420000;
pub const IQK_REJECT_E9C: u32 = 0x00420000;
pub const IQK_E94_MASK: u32 = 0x03ff0000;

/// Build IQK skeleton (gen2 path-A, longer than gen1 by additional
/// path-switch and AGC setup writes).
pub fn build_iqk_path_a_sequence(buf: &mut [IqkStep]) -> usize {
    if buf.len() < IQK_PATH_A_STEP_COUNT {
        return 0;
    }
    buf[0]  = IqkStep { reg: REG_FPGA0_IQK,     val: 0 };
    buf[1]  = IqkStep { reg: REG_S0S1_PATH_SWITCH, val: 0 };
    buf[2]  = IqkStep { reg: REG_TX_IQK_TONE_A, val: 0 };
    buf[3]  = IqkStep { reg: REG_RX_IQK_TONE_A, val: 0 };
    buf[4]  = IqkStep { reg: REG_TX_IQK_PI_A,   val: 0 };
    buf[5]  = IqkStep { reg: REG_RX_IQK_PI_A,   val: 0 };
    buf[6]  = IqkStep { reg: REG_TX_IQK,        val: 0 };
    buf[7]  = IqkStep { reg: REG_RX_IQK,        val: 0 };
    buf[8]  = IqkStep { reg: REG_IQK_AGC_RSP,   val: 0 };
    buf[9]  = IqkStep { reg: REG_IQK_AGC_PTS,   val: 0 };
    buf[10] = IqkStep { reg: REG_IQK_AGC_PTS,   val: 0 };
    buf[11] = IqkStep { reg: REG_FPGA0_RF_MODE, val: 0 };
    IQK_PATH_A_STEP_COUNT
}

pub fn iqk_passed(reg_eac: u32, reg_e94: u32, reg_e9c: u32) -> bool {
    (reg_eac & IQK_PASS_BIT_EAC) == 0
        && (reg_e94 & IQK_E94_MASK) != IQK_REJECT_E94
        && (reg_e9c & IQK_E94_MASK) != IQK_REJECT_E9C
}

// ── LC calibration ─────────────────────────────────────────────────

/// 8821CU LC-cal runs against path A only.
pub const LC_CAL_PATH_COUNT: usize = 1;

// ── Channel-set sequence (dual-band, 2.4 + 5 GHz) ──────────────────

/// 2.4 GHz channel range.
pub const CHANNEL_2G_MIN: u8 = 1;
pub const CHANNEL_2G_MAX: u8 = 14;

/// 5 GHz UNII-1 channel range (36..48, 5180..5240 MHz).
pub const CHANNEL_5G_UNII1_MIN: u8 = 36;
pub const CHANNEL_5G_UNII1_MAX: u8 = 48;

/// 5 GHz UNII-2 channel range (52..64).
pub const CHANNEL_5G_UNII2_MIN: u8 = 52;
pub const CHANNEL_5G_UNII2_MAX: u8 = 64;

/// 5 GHz UNII-3 channel range (149..165).
pub const CHANNEL_5G_UNII3_MIN: u8 = 149;
pub const CHANNEL_5G_UNII3_MAX: u8 = 165;

/// Validate a channel number across all supported bands.
pub fn channel_valid(channel: u8) -> bool {
    (CHANNEL_2G_MIN..=CHANNEL_2G_MAX).contains(&channel)
        || (CHANNEL_5G_UNII1_MIN..=CHANNEL_5G_UNII1_MAX).contains(&channel)
        || (CHANNEL_5G_UNII2_MIN..=CHANNEL_5G_UNII2_MAX).contains(&channel)
        || (CHANNEL_5G_UNII3_MIN..=CHANNEL_5G_UNII3_MAX).contains(&channel)
}

/// Predicate: channel is in the 5 GHz UNII bands.
pub fn channel_is_5ghz(channel: u8) -> bool {
    (CHANNEL_5G_UNII1_MIN..=CHANNEL_5G_UNII1_MAX).contains(&channel)
        || (CHANNEL_5G_UNII2_MIN..=CHANNEL_5G_UNII2_MAX).contains(&channel)
        || (CHANNEL_5G_UNII3_MIN..=CHANNEL_5G_UNII3_MAX).contains(&channel)
}

/// Decode an 802.11 channel number to centre frequency (MHz).
///
/// Specifically validates the canonical "channel 36 = 5180 MHz" target
/// called out in the bring-up brief.
pub fn channel_freq_mhz_8821c(channel: u8) -> u32 {
    match channel {
        1..=13 => 2407 + (channel as u32) * 5,
        14 => 2484,
        36..=64 => 5180 + ((channel as u32 - 36) * 5),
        149..=165 => 5745 + ((channel as u32 - 149) * 5),
        _ => 0,
    }
}

/// Build the channel-set RF writes for 8821CU.
///
/// For 2.4 GHz: just the path-A RF MODE_AG channel write.
/// For 5 GHz: extra `REG_RF_MODE_AG` write to enter A-band first.
///
/// Source: `rtw8821c.c::rtw8821c_set_channel_rf` L310..L360.
pub fn channel_set_writes_8821c(channel: u8) -> alloc::vec::Vec<(u16, u32)> {
    use super::phy::{lssi_encode, REG_FPGA0_LSSI_A};
    use alloc::vec::Vec;
    let mut v = Vec::with_capacity(2);
    if channel_is_5ghz(channel) {
        // Band-switch hint: REG_RF_MODE_AG[16] = 1 means A-band.
        v.push((REG_RF_MODE_AG, 0x00010000));
    }
    v.push((REG_FPGA0_LSSI_A, lssi_encode(RF6052_REG_MODE_AG, channel as u32)));
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

pub fn init_rf<W: FnMut(u8, u32)>(write_rfreg: W) -> usize {
    super::phy_tables::apply_rf_table(RADIO_A_INIT_TABLE, write_rfreg)
}

/// Build USB control-transfer setup for APS_FSMCO MAC enable.
pub fn aps_fsmco_mac_enable_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_APS_FSMCO as u16 + 1, 1)
}

extern crate alloc;
