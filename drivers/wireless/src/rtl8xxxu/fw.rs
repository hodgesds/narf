//! RTL8XXXU firmware blob name resolution.
//!
//! Each chip family loads a separate firmware blob from the
//! `rtlwifi/` firmware subdirectory. This module maps `ChipFamily`
//! to the canonical blob path and provides a helper that looks up
//! the blob via the NARF firmware registry (same pattern as RTW88).
//!
//! ## Firmware download
//!
//! Unlike PCIe RTW88, the USB parts load firmware over USB bulk-OUT
//! in pages of `RTL_FW_PAGE_SIZE` (4096 bytes), prefixed with a
//! single-byte page-number H2C command. The full download sequence is:
//!
//! 1. Assert `MCU_FW_RAM_SEL (bit 6)` in `REG_MCU_FW_DL`.
//! 2. For each 4 KiB page: send via bulk-OUT on the H2C endpoint.
//! 3. Poll `REG_MCU_FW_DL` until the firmware sets the ready bit.
//!
//! The detailed per-chip download is deferred; this file only exposes
//! the name-resolution layer needed by the smokes.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c`
//!   `rtl8xxxu_load_firmware` (~L7800..L7850).
//! - `drivers/net/wireless/realtek/rtl8xxxu/8188e.c`
//!   `rtl8188eu_fops.load_firmware` string.

#![allow(dead_code)]

use super::regs::ChipFamily;

/// Resolve the firmware blob path for a chip family.
///
/// Returns `None` for `ChipFamily::Unknown`.
///
/// Source: kernel MODULE_FIRMWARE() strings in each per-chip `.c` file,
/// cross-referenced with `firmware/` entries in the kernel tree.
///
/// | Family     | Blob path                    |
/// |------------|------------------------------|
/// | RTL8188EU  | `rtlwifi/rtl8188eufw.bin`    |
/// | RTL8192EU  | `rtlwifi/rtl8192eufw.bin`    |
/// | RTL8723BU  | `rtlwifi/rtl8723bufw.bin`    |
/// | RTL8821CU  | `rtlwifi/rtl8821cufw.bin`    |
/// | RTL8822BU  | `rtlwifi/rtl8822bufw.bin`    |
pub const fn firmware_name(chip: ChipFamily) -> Option<&'static str> {
    chip.firmware_name()
}

/// Firmware version info extracted from the blob header.
///
/// The RTL8XXXU firmware blob begins with a short header:
/// `signature[4] + version[1] + subversion[1] + rsvd[2]`.
///
/// Source: `rtl8xxxu.h::rtl8xxxu_firmware_header` struct definition.
#[derive(Copy, Clone, Debug)]
pub struct FwHeader {
    /// 4-byte firmware signature. Realtek chips use `RTL8188E`, etc.
    pub signature: [u8; 4],
    /// Major version byte.
    pub version: u8,
    /// Sub-version byte.
    pub subversion: u8,
}

impl FwHeader {
    /// Minimum blob size in bytes that a valid Realtek FW blob must have.
    pub const MIN_BLOB_SIZE: usize = 8;

    /// Parse the first 8 bytes of a firmware blob.
    pub fn parse(blob: &[u8]) -> Option<Self> {
        if blob.len() < Self::MIN_BLOB_SIZE {
            return None;
        }
        Some(Self {
            signature: [blob[0], blob[1], blob[2], blob[3]],
            version: blob[4],
            subversion: blob[5],
        })
    }
}

/// Per-chip firmware page counts and total sizes.
///
/// `RTL_FW_PAGE_SIZE = 4096`. Total firmware size varies by chip;
/// a real blob is typically 14-18 KiB. We store the page count to
/// drive the bulk-OUT loop.
#[derive(Copy, Clone, Debug)]
pub struct FwLayout {
    /// Number of 4 KiB pages in the firmware.
    pub page_count: u8,
    /// Total firmware size in bytes (may be < page_count × PAGE_SIZE
    /// if the last page is partially filled).
    pub total_bytes: usize,
}

impl FwLayout {
    /// Compute layout from a blob length.
    pub fn from_blob_len(len: usize) -> Self {
        use super::regs::RTL_FW_PAGE_SIZE;
        let page_count = ((len + RTL_FW_PAGE_SIZE - 1) / RTL_FW_PAGE_SIZE) as u8;
        Self { page_count, total_bytes: len }
    }
}
