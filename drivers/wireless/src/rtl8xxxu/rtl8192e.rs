//! RTL8192EU chip constants, PHY tables, RF tables, IQ/LC cal.
//!
//! RTL8192EU: 802.11n 2x2 USB (RTL8191EU is the 1T2R bonding).
//! USB IDs: `0x0BDA:0x818B` (native), plus OEM variants.
//! Firmware: `rtlwifi/rtl8192eu_nic.bin` (`8192e.c::rtl8192eu_load_firmware`).
//!
//! ## Per-chip integration
//!
//! The 8192EU is a gen2 rtl8xxxu chip (`rtl8192eu_fops`): H2C via
//! `rtl8xxxu_gen2_h2c_cmd`, gen2 channel config, TX descriptor v2 (40 B),
//! RX descriptor 24 B and firmware rate adaptation. Identity, EFUSE, power
//! and the H2C mailbox live in `rtl8192e_init`.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/8192e.c`
//!   - `rtl8192e_mac_init_table[]`, `rtl8192eu_phy_init_table[]`,
//!     `rtl8xxx_agc_8192eu_{std,highpa}_table[]`,
//!     `rtl8192eu_radio{a,b}_init_table[]`.
//!   - `rtl8192eu_init_phy_bb()`, `rtl8192eu_init_phy_rf()`.
//!   - `rtl8192eu_iqk_path_{a,b}()`, `rtl8192eu_phy_iqcalibrate()`
//!     (implemented in `rtl8192e_iqk`).
//!   - `rtl8192eu_fops`.

#![allow(dead_code)]

use super::regs::*;
use super::usb::UsbControlSetup;

/// Chip name string.
pub const CHIP_NAME: &str = "RTL8192EU";

/// Firmware blob path (`rtl8192eu_load_firmware`).
pub const FIRMWARE_NAME: &str = "rtlwifi/rtl8192eu_nic.bin";

/// `rtl8192eu_fops.writeN_block_size`.
pub const WRITEN_BLOCK_SIZE: usize = 128;

/// `rtl8192eu_fops.trxff_boundary`.
pub const TRXFF_BOUNDARY: u16 = 0x3cff;

/// TX total pages. `TX_TOTAL_PAGE_NUM_8192E = 0xF3`.
pub const TX_TOTAL_PAGES: u8 = TX_TOTAL_PAGE_NUM_8192E;

/// TX high-priority page count. `TX_PAGE_NUM_HI_PQ_8192E = 0x08`.
pub const TX_PAGE_NUM_HI: u8 = 0x08;
/// TX low-priority page count. `TX_PAGE_NUM_LO_PQ_8192E = 0x0C`.
pub const TX_PAGE_NUM_LO: u8 = 0x0C;
/// TX normal-priority page count. `TX_PAGE_NUM_NORM_PQ_8192E = 0x00`.
pub const TX_PAGE_NUM_NORM: u8 = 0x00;

/// TX descriptor size: `sizeof(struct rtl8xxxu_txdesc40)`.
pub const TX_DESC_SIZE: usize = TXDESC_SIZE_40;
/// RX descriptor size: `sizeof(struct rtl8xxxu_rxdesc24)`.
pub const RX_DESC_SIZE: usize = RXDESC_SIZE_24;

/// LDO 1.2V control register.
/// `REG_8192E_LDOV12_CTRL = 0x0014`. `regs.h` L70.
pub const REG_8192E_LDOV12_CTRL: u16 = 0x0014;
/// LDO 1.2V enable bit.
pub const LDOV12_ENABLE: u8 = 0x01;

// ── Row-count constants (Linux tables, sentinel excluded) ─────────

/// Rows of `rtl8192e_mac_init_table[]`.
pub const N_MAC_ROWS: usize = MAC_INIT_TABLE.len() - 1;
/// Rows of `rtl8192eu_phy_init_table[]`.
pub const N_PHY_ROWS: usize = PHY_INIT_TABLE.len() - 1;
/// Rows of `rtl8xxx_agc_8192eu_std_table[]`.
pub const N_AGC_STD_ROWS: usize = AGC_STD_TABLE.len() - 1;
/// Rows of `rtl8xxx_agc_8192eu_highpa_table[]`.
pub const N_AGC_HIGHPA_ROWS: usize = AGC_HIGHPA_TABLE.len() - 1;
/// Rows of `rtl8192eu_radioa_init_table[]`.
pub const N_RF_A_ROWS: usize = RADIO_A_INIT_TABLE.len() - 1;
/// Rows of `rtl8192eu_radiob_init_table[]`.
pub const N_RF_B_ROWS: usize = RADIO_B_INIT_TABLE.len() - 1;

/// Stage 0 / 1 register init table for RTL8192EU.
pub const INIT_TABLE: &[(u16, u8)] = &[
    (REG_8192E_LDOV12_CTRL, LDOV12_ENABLE),
    (REG_APS_FSMCO + 1, 0x08),
    (REG_CR, (CR_OPEN_8188E & 0xFF) as u8),
    (REG_CR + 1, ((CR_OPEN_8188E >> 8) & 0xFF) as u8),
];

/// Chip-init stage-0 register bank.
pub fn stage0_register_bank() -> &'static [(u16, u8)] {
    INIT_TABLE
}

// ── Per-chip tables (generated verbatim from `8192e.c`) ───────────

pub use super::rtl8192e_tables::{
    AGC_HIGHPA_TABLE, AGC_STD_TABLE, MAC_INIT_TABLE, PHY_INIT_TABLE, RADIO_A_INIT_TABLE,
    RADIO_B_INIT_TABLE,
};

/// Path count for this chip. 8192EU is 2T2R.
pub const NUM_RF_PATHS: usize = 2;

// ── Calibration ────────────────────────────────────────────────────
//
// LC calibration and the two-path IQK (`rtl8192eu_phy_iq_calibrate`) are
// implemented against the owner in `rtl8192e_iqk`.

// ── Channel-set sequence ───────────────────────────────────────────
//
// 8192EU is 2.4 GHz only. The gen2 channel programming
// (`core.c::rtl8xxxu_gen2_config_channel`) lives in `rtl8192e_radio`.

pub const CHANNEL_MIN: u8 = 1;
pub const CHANNEL_MAX: u8 = 14;

/// Validate a 2.4 GHz channel number.
pub fn channel_valid(channel: u8) -> bool {
    (CHANNEL_MIN..=CHANNEL_MAX).contains(&channel)
}

// ── Init function wiring (Stage-2 hookup) ──────────────────────────

/// Apply MAC init table.
pub fn init_mac<W: FnMut(u16, u8)>(write8: W) -> usize {
    super::phy_tables::apply_mac_table(MAC_INIT_TABLE, write8)
}

/// Apply PHY/BB + AGC tables. Uses the standard AGC table by default;
/// for high-PA variants, callers swap to `AGC_HIGHPA_TABLE`.
pub fn init_phy<W: FnMut(u16, u32)>(mut write32: W) -> usize {
    let phy = super::phy_tables::apply_phy_table(PHY_INIT_TABLE, &mut write32);
    let agc = super::phy_tables::apply_phy_table(AGC_STD_TABLE, &mut write32);
    phy + agc
}

/// Apply both RF path init tables.
pub fn init_rf<W: FnMut(u8, u8, u32)>(mut write_rfreg: W) -> usize {
    use super::phy::RfPath;
    let mut a = 0usize;
    a += super::phy_tables::apply_rf_table(RADIO_A_INIT_TABLE, |r, v| {
        write_rfreg(RfPath::A.index(), r, v)
    });
    a += super::phy_tables::apply_rf_table(RADIO_B_INIT_TABLE, |r, v| {
        write_rfreg(RfPath::B.index(), r, v)
    });
    a
}

// ── USB control-transfer setup helpers ─────────────────────────────

pub fn ldo12_enable_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_8192E_LDOV12_CTRL, 1)
}

pub fn cr_open_setups() -> [UsbControlSetup; 2] {
    [
        UsbControlSetup::write(REG_CR, 1),
        UsbControlSetup::write(REG_CR + 1, 1),
    ]
}
