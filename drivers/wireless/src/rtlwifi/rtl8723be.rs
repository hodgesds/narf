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

#![allow(dead_code)]

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
