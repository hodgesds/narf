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

    /// Skip the firmware header (first 32 bytes for the canonical Realtek
    /// format) and return the payload slice.
    ///
    /// Source: `rtl8xxxu_firmware_header` in `rtl8xxxu.h` is 32 bytes.
    pub fn strip_header(blob: &[u8]) -> &[u8] {
        const HDR: usize = 32;
        if blob.len() <= HDR { &[] } else { &blob[HDR..] }
    }

    /// Iterator over 4 KiB firmware pages.
    pub fn pages<'a>(&self, blob: &'a [u8]) -> FwPageIter<'a> {
        FwPageIter { blob, pos: 0, page_idx: 0 }
    }
}

/// Iterator over firmware pages.
pub struct FwPageIter<'a> {
    blob: &'a [u8],
    pos: usize,
    page_idx: u8,
}

impl<'a> Iterator for FwPageIter<'a> {
    type Item = (u8, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        use super::regs::RTL_FW_PAGE_SIZE;
        if self.pos >= self.blob.len() {
            return None;
        }
        let end = (self.pos + RTL_FW_PAGE_SIZE).min(self.blob.len());
        let slice = &self.blob[self.pos..end];
        let idx = self.page_idx;
        self.pos = end;
        self.page_idx = self.page_idx.wrapping_add(1);
        Some((idx, slice))
    }
}

// ── Download protocol steps ──────────────────────────────────────────

/// One step in the FW download protocol.
///
/// Source: `core.c::rtl8xxxu_download_firmware` L2004..L2104 and
/// `core.c::rtl8xxxu_start_firmware` L1925..L2003.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwDlStep {
    Read8 { addr: u16 },
    Read16 { addr: u16 },
    Read32 { addr: u16 },
    Write8 { addr: u16, val: u8 },
    Write16 { addr: u16, val: u16 },
    Write32 { addr: u16, val: u32 },
    /// Read-modify-write 8-bit: `(cur & keep) | set`.
    Write8RMW { addr: u16, keep: u8, set: u8 },
    /// Bulk-OUT page transfer: `len` bytes starting at `REG_FW_START_ADDRESS`.
    PageOut { page_idx: u8, len: usize },
    /// Poll until `(cur & mask) == match_val` or `max` iterations elapse.
    Poll32 { addr: u16, mask: u32, match_val: u32, max: usize },
}

/// Build the deterministic FW-download plan for non-RTL8710B / non-RTL8192F
/// targets.
pub fn fw_download_plan(fw_payload: &[u8]) -> alloc::vec::Vec<FwDlStep> {
    use super::regs::{
        FW_POLL_MAX, MCU_FW_DL_CSUM_REPORT, MCU_FW_DL_ENABLE, MCU_FW_DL_READY,
        MCU_WINT_INIT_READY, REG_HMTFR, REG_MCU_FW_DL, REG_SYS_FUNC,
        RTL_FW_PAGE_SIZE, SYS_FUNC_CPU_ENABLE,
    };
    use alloc::vec::Vec;
    let mut plan: Vec<FwDlStep> = Vec::with_capacity(32);

    // SYS_FUNC byte 1 |= 4 — enables 8051.
    plan.push(FwDlStep::Write8RMW { addr: REG_SYS_FUNC + 1, keep: 0xFF, set: 0x04 });
    // SYS_FUNC |= CPU_ENABLE.
    plan.push(FwDlStep::Read16 { addr: REG_SYS_FUNC });
    plan.push(FwDlStep::Write16 { addr: REG_SYS_FUNC, val: SYS_FUNC_CPU_ENABLE });
    // If FW already loaded, hard-reset.
    plan.push(FwDlStep::Read8 { addr: REG_MCU_FW_DL });
    plan.push(FwDlStep::Write8 { addr: REG_MCU_FW_DL, val: 0x00 });
    // Enable FW download.
    plan.push(FwDlStep::Write8RMW { addr: REG_MCU_FW_DL, keep: 0xFF, set: MCU_FW_DL_ENABLE });
    // 8051 reset — clear bit 19.
    plan.push(FwDlStep::Read32 { addr: REG_MCU_FW_DL });
    plan.push(FwDlStep::Write32 { addr: REG_MCU_FW_DL, val: 0 });
    // Reset CSUM report.
    plan.push(FwDlStep::Write8RMW { addr: REG_MCU_FW_DL, keep: 0xFF, set: MCU_FW_DL_CSUM_REPORT });

    let pages = fw_payload.len() / RTL_FW_PAGE_SIZE;
    let remainder = fw_payload.len() % RTL_FW_PAGE_SIZE;
    for i in 0..pages {
        plan.push(FwDlStep::Write8RMW { addr: REG_MCU_FW_DL + 2, keep: 0xF8, set: i as u8 });
        plan.push(FwDlStep::PageOut { page_idx: i as u8, len: RTL_FW_PAGE_SIZE });
    }
    if remainder != 0 {
        plan.push(FwDlStep::Write8RMW { addr: REG_MCU_FW_DL + 2, keep: 0xF8, set: pages as u8 });
        plan.push(FwDlStep::PageOut { page_idx: pages as u8, len: remainder });
    }

    // Disable FW download.
    plan.push(FwDlStep::Read16 { addr: REG_MCU_FW_DL });
    plan.push(FwDlStep::Write16 { addr: REG_MCU_FW_DL, val: 0 });

    // Poll for CSUM report.
    plan.push(FwDlStep::Poll32 {
        addr: REG_MCU_FW_DL,
        mask: MCU_FW_DL_CSUM_REPORT as u32,
        match_val: MCU_FW_DL_CSUM_REPORT as u32,
        max: FW_POLL_MAX,
    });
    // Mark FW ready.
    plan.push(FwDlStep::Write32 { addr: REG_MCU_FW_DL, val: MCU_FW_DL_READY as u32 });
    // 8051 reset.
    plan.push(FwDlStep::Read16 { addr: REG_SYS_FUNC });
    plan.push(FwDlStep::Write16 { addr: REG_SYS_FUNC, val: 0 });
    plan.push(FwDlStep::Write16 { addr: REG_SYS_FUNC, val: SYS_FUNC_CPU_ENABLE });
    // Wait FW ready.
    plan.push(FwDlStep::Poll32 {
        addr: REG_MCU_FW_DL,
        mask: MCU_WINT_INIT_READY,
        match_val: MCU_WINT_INIT_READY,
        max: FW_POLL_MAX,
    });
    // H2C init mark.
    plan.push(FwDlStep::Write8 { addr: REG_HMTFR, val: 0x0F });

    plan
}

/// USB control setup for the per-page selector write.
pub fn page_selector_setup() -> super::usb::UsbControlSetup {
    use super::regs::REG_MCU_FW_DL;
    super::usb::UsbControlSetup::write(REG_MCU_FW_DL + 2, 1)
}

extern crate alloc;
