//! RTL8192CE per-chip constants.
//!
//! RTL8192CE (and its closely-related RTL8192DE) is a 2T2R 802.11n PCIe NIC.
//! The register layout is essentially the 8188EE layout extended with dual-RF
//! paths.  This file covers both the 8192CE (`0x8178`) and 8192DE (`0x8193`)
//! device IDs since they share the same driver class in Linux.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8192ce/reg.h`  — register offsets
//! - `rtlwifi/rtl8192ce/def.h`  — chip-version and rate constants
//! - `rtlwifi/rtl8192de/reg.h`  — minor offset additions (mostly identical)
//!
//! ## Retained-runtime foundation (`rtl8192ce/`)
//!
//! Exact Linux `rtl8192ce` + `rtl8192c` (common) pieces a native
//! RTL8192CE / RTL8188CE owner is built from:
//!
//! - [`version`] — `_rtl92ce_read_chip_version`, the `fw_common.h` version
//!   predicates, RF-type qualification (1T1R `CHIP_88C`, 2T2R `CHIP_92C`;
//!   1T2R bonding, test chips and unknown cuts refused) and the
//!   `rtl92c_init_sw_vars` firmware-name selection.
//! - [`adapter`] — `rtl92ce_read_eeprom_info` / `_rtl92ce_read_adapter_info`
//!   factory facts, BT-coexist EFUSE fields and the OEM rule.
//! - [`power`] — the `_rtl92ce_init_mac` power-on prefix (no pwrseq table).
//! - [`fw`] — `rtl8192cfw*.bin` header validation and `rtl92c_download_fw`
//!   (normal-chip paged write, `_rtl92c_fw_free_to_go`,
//!   `rtl92c_firmware_selfreset`).
//! - [`trx`] — 64-byte linked TX ring entries (40-byte descriptor, next link
//!   at dword 10) and 32-byte RX descriptors (`trx.{c,h}`); the ring owner
//!   is `prepare::Chip::Rtl8192ce`.
//! - [`tables`] — verbatim `table.c` MAC / PHY_REG (1T, 2T) / PHY_REG_PG /
//!   AGC (1T, 2T) / RADIOA / RADIOB arrays (generated).
//! - [`llt`] — `_rtl92ce_llt_table_init` (`LLT_CONFIG == 5`).
//! - [`mac`] — the `_rtl92ce_init_mac` remainder, `_rtl92ce_hw_configure`
//!   and the station address, with `REG_CR` and ring bases left to the
//!   packet owner.
//! - [`phy`] — BB/RF serial access, `rtl92c_phy_mac/bb/rf_config` over the
//!   tables, UMC-cut RF fixups, 20/40 MHz bandwidth, `RF_CHNLBW` channel
//!   step, `_rtl92ce_phy_lc_calibrate` and the RF path switch.
//! - [`txpower`] — `_rtl92ce_read_txpower_info_from_hwpg` and the RF6052
//!   CCK/OFDM TXAGC writes of `rtl92c_phy_set_txpower_level`.
//! - [`iqk`] — `rtl92c_phy_iq_calibrate` for 1T1R and 2T2R.
//! - [`channel`] — the `rtl_op_config` channel + bandwidth order.
//! - [`h2c`] — `rtl92c_fill_h2c_cmd`, SETPWRMODE / JOINBSSRPT / RA-mask
//!   payloads, RPWM and the 92C interrupt profile.
//! - [`init`] — the `rtl92ce_hw_init` tail after the firmware download
//!   (run by `Prepared::configure_rtl8192ce`).
//! - [`ps`] — media status, AID, beacon control, `rtl92c_dm_rf_saving`,
//!   false-alarm statistics and `_rtl92ce_poweroff_adapter`, composed by the
//!   linked-ring packet owner branch (`rtl8192ce/packet_owner.rs`, mounted
//!   as `prepare::packet::ce92`).

#![allow(dead_code)]

pub mod adapter;
pub mod channel;
pub mod envelope;
pub mod fw;
pub mod h2c;
pub mod init;
pub mod iqk;
pub mod llt;
pub mod mac;
pub mod phy;
pub mod power;
pub mod ps;
pub mod tables;
pub mod trx;
pub mod txpower;
pub mod version;

#[cfg(any(test, feature = "kernel-test"))]
mod phy_tests;
#[cfg(any(test, feature = "kernel-test"))]
mod ps_tests;
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests;

/// Further `rtl92ce_pci_ids` entries (`rtl8192ce/sw.c`) beside the two
/// `regs.rs` IDs.
pub const DEV_ID_8192CE_8177: u16 = 0x8177;
pub const DEV_ID_8192CE_8191: u16 = 0x8191;

/// Whether `did` is one of the `rtl92ce_pci_ids` (RTL8192CE / RTL8188CE).
pub const fn is_8192ce(did: u16) -> bool {
    matches!(
        did,
        DEV_ID_8192CE | DEV_ID_8192CE_ALT | DEV_ID_8192CE_8177 | DEV_ID_8192CE_8191
    )
}

/// Primary PCI device ID for RTL8192CE.
pub const DEV_ID_8192CE: u16 = super::regs::RTL_DEV_8192CE;

/// Alternate PCI device ID (some board SKUs).
pub const DEV_ID_8192CE_ALT: u16 = super::regs::RTL_DEV_8192CE_ALT;

/// PCI device ID for RTL8192DE (dual-band variant).
pub const DEV_ID_8192DE: u16 = super::regs::RTL_DEV_8192DE;

// ── Per-chip register bank ────────────────────────────────────────────────

/// Mapped IO range size (16 KiB).
/// `rtlwifi/pci.h::RTL_MEM_MAPPED_IO_RANGE_8192CE`.
pub const MMIO_SIZE: usize = 0x4000;

/// EFUSE logical map size (512 bytes for RTL8192CE).
/// Source: `rtl8192ce/hw.c` EFUSE_MAP_LEN.
pub const EFUSE_MAP_SIZE: usize = 512;

// ── Chip version identifiers ──────────────────────────────────────────────
//
// Source: `rtl8192ce/def.h::enum version_8192c`.

/// A-cut test chip (88C).
pub const VERSION_A_CHIP_88C: u16 = 0x00;
/// A-cut test chip (92C).
pub const VERSION_A_CHIP_92C: u16 = 0x01;
/// B-cut normal 92C.
pub const VERSION_B_CHIP_92C: u16 = 0x11;
/// B-cut normal 88C.
pub const VERSION_B_CHIP_88C: u16 = 0x10;

// ── TX/RX descriptor helpers ──────────────────────────────────────────────
//
// The 8192CE uses the same 16-dword TX + 8-dword RX layout as 8188EE.
// Re-export from 8188EE module to avoid duplication.

pub use super::rtl8188ee::{RxDesc, TxDesc};

/// TX descriptor OWN bit (bit 31 of DW0).
pub const TX_OWN_BIT: u32 = super::rtl8188ee::TX_OWN_BIT;

/// RX descriptor OWN bit (bit 31 of DW0).
pub const RX_OWN_BIT: u32 = super::rtl8188ee::RX_OWN_BIT;
