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

#![allow(dead_code)]

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
