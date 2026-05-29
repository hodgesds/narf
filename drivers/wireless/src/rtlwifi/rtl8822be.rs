//! RTL8822BE per-chip constants.
//!
//! RTL8822BE is a 2T2R 802.11ac Wave-2 PCIe NIC.  In Linux it is handled by
//! the `rtl8821ae` driver (same driver, different chip config).  The `rtw88`
//! generation later added an `RTL8822BE` entry in `rtw88/pci.c`, but the
//! original RTL8822BE hardware ships under the `rtlwifi/rtl8821ae` driver.
//!
//! Device ID `0xB822` is also listed in `rtw88/pci.c` for newer silicon
//! revisions.  NARF separates them by driver epoch: this file covers the
//! legacy rtlwifi binding; `rtw88` covers the newer binding.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8821ae/` — shared driver for 8821AE + 8822BE
//! - `rtlwifi/pci.h::RTL_PCI_8822BE_DID = 0xB822`

#![allow(dead_code)]

/// PCI device ID (shared with the rtw88 era; this binding handles the
/// older hardware revision from the rtlwifi driver epoch).
pub const DEV_ID: u16 = super::regs::RTL_DEV_8822BE;

// ── Per-chip register bank ────────────────────────────────────────────────

/// Mapped IO range size (16 KiB).
pub const MMIO_SIZE: usize = 0x4000;

/// EFUSE logical map size (512 bytes).
pub const EFUSE_MAP_SIZE: usize = 512;

// ── TX descriptor ring count ──────────────────────────────────────────────
//
// Source: `rtlwifi/pci.h::TX_DESC_NUM_8822B`.

/// TX descriptor count for RTL8822BE (larger ring).
pub const TX_DESC_NUM: usize = 512;

// ── VHT support ──────────────────────────────────────────────────────────

/// Maximum number of spatial streams.
pub const NUM_SPATIAL_STREAMS: u8 = 2;

// ── TX/RX descriptor ─────────────────────────────────────────────────────

pub use super::rtl8188ee::{RxDesc, TxDesc};
