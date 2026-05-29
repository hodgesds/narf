//! RTL8821AE per-chip constants.
//!
//! RTL8821AE is a 1T1R 802.11ac (Wi-Fi 5) PCIe NIC covering both 2.4 GHz
//! and 5 GHz bands.  Shipped from ~2014 in mid-range laptops.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8821ae/reg.h`  — register offsets
//! - `rtlwifi/rtl8821ae/def.h`  — rate / VHT constants

#![allow(dead_code)]

/// PCI device ID.
pub const DEV_ID: u16 = super::regs::RTL_DEV_8821AE;

// ── Per-chip register bank ────────────────────────────────────────────────

/// Mapped IO range size (16 KiB).
pub const MMIO_SIZE: usize = 0x4000;

/// EFUSE logical map size (512 bytes).
/// Source: `rtl8821ae/hw.c`.
pub const EFUSE_MAP_SIZE: usize = 512;

// ── VHT/HT rate constants ─────────────────────────────────────────────────
//
// Source: `rtl8821ae/def.h`.

/// VHT 1SS MCS0.
pub const MGN_VHT1SS_MCS0: u8 = 0x90;
/// VHT 1SS MCS9.
pub const MGN_VHT1SS_MCS9: u8 = 0x99;
/// VHT 2SS MCS0.
pub const MGN_VHT2SS_MCS0: u8 = 0x9A;
/// VHT 2SS MCS9.
pub const MGN_VHT2SS_MCS9: u8 = 0xA3;

// ── TX/RX descriptor ─────────────────────────────────────────────────────

pub use super::rtl8188ee::{RxDesc, TxDesc};
