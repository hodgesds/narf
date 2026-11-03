//! RTL8723BE per-chip constants.
//!
//! RTL8723BE is a 1T1R 802.11n + Bluetooth 4.0 combo PCIe NIC from ~2013.
//! Extremely common in Intel-platform laptops from that era (HP, Lenovo,
//! Acer).  The RTL8723AE is the earlier (A-cut) sibling with device ID
//! 0x8723; both share this driver class.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8723be/reg.h`  — register offsets
//! - `rtlwifi/rtl8723be/def.h`  — chip-version constants
//! - `rtlwifi/rtl8723ae/reg.h`  — A-cut (device 0x8723), near-identical
//!
//! ## Retained runtime (`rtl8723be/`, in progress)
//!
//! Exact Linux `rtl8723be` + `rtl8723com` pieces the native RTL8723BE owner
//! is built from. RTL8723BE is not admitted yet (probe keeps it diagnostic).
//!
//! - [`version`] — `_rtl8723be_read_chip_version` (`CHIP_8723B` required;
//!   every cut, SMIC vendor bit) and the `rtl8723befw_36.bin` /
//!   `rtl8723befw.bin` names.
//! - [`adapter`] — `rtl8723be_read_eeprom_info` / `_rtl8723be_read_adapter_info`
//!   factory facts, the BT-coexist / antenna-number / single-antenna-path
//!   facts of `rtl8723be_read_bt_coexist_info_from_hwpg`, thermal meter,
//!   regulatory, package type and the OEM rule.
//! - [`pwrseq`] — PCI rows of every `rtl8723B_*_flow` (`pwrseq.{c,h}`).
//! - [`fw`] — header validation and `rtl8723_download_fw` with the
//!   8723BE 8051 self-reset.
//! - [`trx`] — 64-byte linked TX ring entries (40-byte descriptor, buffer at
//!   dword 10, next link at dword 12), `rtl8723be_tx_fill_desc` /
//!   `rtl8723be_tx_fill_cmddesc` and the `rtl8723be_rx_query_desc` status.
//! - [`llt`] — `_rtl8723be_llt_table_init` (boundary 245).
//! - [`mac`] — the `_rtl8723be_init_mac` remainder in its three segments
//!   around the owner's `REG_CR` writes and LLT, `_rtl8723be_hw_configure`
//!   and the station address.

#![allow(dead_code)]

pub mod adapter;
pub mod fw;
pub mod llt;
pub mod mac;
pub mod pwrseq;
pub mod trx;
pub mod version;

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests;

/// PCI device ID for RTL8723BE (B-cut).
pub const DEV_ID_BE: u16 = super::regs::RTL_DEV_8723BE;

/// PCI device ID for RTL8723AE (A-cut sibling).
pub const DEV_ID_AE: u16 = super::regs::RTL_DEV_8723AE;

// ── Per-chip register bank ────────────────────────────────────────────────

/// Mapped IO range size (16 KiB).
pub const MMIO_SIZE: usize = 0x4000;

/// EFUSE logical map size (256 bytes for 8723 series).
/// Source: `rtl8723be/hw.c`.
pub const EFUSE_MAP_SIZE: usize = 256;

// ── Bluetooth coexistence ─────────────────────────────────────────────────
//
// The 8723BE has an internal BT co-existence controller.  These register
// bits are used by the BT co-ex code; included here for future reference.

/// `REG_LEDCFG0` offset — shared with btcoex in `rtl8723be/hw.c`.
pub use super::regs::REG_HISR;

// ── TX/RX descriptor re-exports ───────────────────────────────────────────

pub use super::rtl8188ee::{RxDesc, TxDesc};
