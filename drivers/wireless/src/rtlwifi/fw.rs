//! rtlwifi firmware blob management.
//!
//! Maps each supported chip to a firmware blob name as used by the Linux
//! firmware loader (`/lib/firmware/rtlwifi/<name>.bin`).  NARF uses the same
//! naming convention so the same blobs work.
//!
//! The actual download sequence (page-write into on-chip SRAM via the H2C
//! channel) is left as a follow-up — this file provides only the blob-name
//! resolution and firmware header constants so that follow-up commits have
//! named constants to work with.
//!
//! ## References (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/rtl8188ee/fw.c` — `rtl88ee_firmware_selfreset`, fw path
//! - `rtlwifi/rtl8192ee/fw.c` — `rtl92ee_download_fw`, blob naming
//! - `rtlwifi/rtl8821ae/fw.c` — `rtl8821ae_download_fw`
//! - Linux module firmware declarations (MODULE_FIRMWARE macros in each sw.c)

#![allow(dead_code)]

extern crate alloc;

use super::regs::*;

// ── Firmware blob names ───────────────────────────────────────────────────
//
// Convention: `rtlwifi/<chip>fw.bin`.  These are the names used by the Linux
// kernel's MODULE_FIRMWARE declarations in the corresponding `sw.c` files.

/// Firmware blob for RTL8188EE.
/// Linux `rtl8188ee/sw.c::MODULE_FIRMWARE("rtlwifi/rtl8188eefw.bin")`.
pub const FW_8188EE: &str = "rtlwifi/rtl8188eefw.bin";

/// Firmware blob for RTL8192CE.
/// Linux `rtl8192ce/sw.c::MODULE_FIRMWARE("rtlwifi/rtl8192cfw.bin")`.
pub const FW_8192CE: &str = "rtlwifi/rtl8192cfw.bin";

/// Firmware blob for RTL8192DE.
/// Linux `rtl8192de/sw.c::MODULE_FIRMWARE("rtlwifi/rtl8192defw.bin")`.
pub const FW_8192DE: &str = "rtlwifi/rtl8192defw.bin";

/// Firmware blob for RTL8192EE.
/// Linux `rtl8192ee/sw.c::MODULE_FIRMWARE("rtlwifi/rtl8192eefw.bin")`.
pub const FW_8192EE: &str = "rtlwifi/rtl8192eefw.bin";

/// Firmware blob for RTL8723AE.
/// Linux `rtl8723ae/sw.c::MODULE_FIRMWARE("rtlwifi/rtl8723aefw.bin")`.
pub const FW_8723AE: &str = "rtlwifi/rtl8723aefw.bin";

/// Firmware blob for RTL8723BE.
/// Linux `rtl8723be/sw.c::MODULE_FIRMWARE("rtlwifi/rtl8723befw.bin")`.
pub const FW_8723BE: &str = "rtlwifi/rtl8723befw.bin";

/// Firmware blob for RTL8821AE.
/// Linux `rtl8821ae/sw.c::MODULE_FIRMWARE("rtlwifi/rtl8821aefw.bin")`.
pub const FW_8821AE: &str = "rtlwifi/rtl8821aefw.bin";

/// Firmware blob for RTL8822BE.
/// Linux `rtl8821ae/sw.c` — 8822BE shares the 8821AE driver in Linux and
/// uses a separate blob: `MODULE_FIRMWARE("rtlwifi/rtl8822befw.bin")`.
pub const FW_8822BE: &str = "rtlwifi/rtl8822befw.bin";

// ── Firmware header constants (RTL8192EE generation) ─────────────────────
//
// Source: `rtlwifi/rtl8192ee/fw.h`.

/// Maximum firmware image size (32 KiB).
pub const FW_MAX_SIZE: usize = 0x8000;

/// Firmware entry start address in on-chip IMEM.
pub const FW_START_ADDRESS: u32 = 0x1000;

/// Page size for paged firmware download (4 KiB).
pub const FW_PAGE_SIZE: usize = 4096;

/// Number of pages needed for `len` bytes.
#[inline]
pub const fn fw_page_count(len: usize) -> usize {
    (len + 127) >> 7 // pagenum_128 — 128-byte pages for H2C staging
}

// ── Blob-name resolver ────────────────────────────────────────────────────

/// Return the firmware blob name for a given PCI device id.
///
/// Returns `None` for unrecognised device IDs.
pub const fn fw_name_for(did: u16) -> Option<&'static str> {
    match did {
        RTL_DEV_8188EE => Some(FW_8188EE),
        RTL_DEV_8192CE | RTL_DEV_8192CE_ALT => Some(FW_8192CE),
        RTL_DEV_8192DE => Some(FW_8192DE),
        RTL_DEV_8192EE => Some(FW_8192EE),
        RTL_DEV_8723AE => Some(FW_8723AE),
        RTL_DEV_8723BE => Some(FW_8723BE),
        RTL_DEV_8821AE => Some(FW_8821AE),
        RTL_DEV_8822BE => Some(FW_8822BE),
        _ => None,
    }
}
