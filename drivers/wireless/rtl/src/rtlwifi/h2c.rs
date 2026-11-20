//! rtlwifi H2C (Host-to-Card) mailbox over MMIO.
//!
//! The rtlwifi family communicates with on-chip firmware through four
//! "HMEBOX" mailboxes (`REG_HMEBOX_{0..3}`, plus extension halves
//! `REG_HMEBOX_EXT_*`).  Each cmd is up to 7 bytes:
//!
//! - 1 byte `element_id` (the cmd selector)
//! - 3 bytes inline payload at `HMEBOX_n`
//! - up to 4 bytes extension payload at `HMEBOX_EXT_n`
//!
//! The firmware reads from one mailbox at a time and clears the
//! corresponding bit in `REG_HMETFR` to ACK; the driver round-robins
//! `boxnum = (boxnum + 1) % 4` after each send.
//!
//! This module supplies the mailbox encoder, the round-robin state, and
//! the wait-for-ACK polling primitive.  Higher-level command builders
//! (set channel, set RF mode, BT-coex commands, etc.) live in the chip's
//! per-feature modules.
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtl8192ee/fw.c::_rtl92ee_fill_h2c_command` (line 163) — the
//!   canonical mailbox writer; this code is byte-for-byte equivalent.
//! - `rtl8192ee/fw.c::_rtl92ee_check_fw_read_last_h2c` (line 151) — ACK
//!   poll via `REG_HMETFR`.
//! - `rtl8821ae/fw.c::_rtl8821ae_fill_h2c_command` — same shape.

#![allow(dead_code)]

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::regs::*;

// ── H2C mailbox register block ───────────────────────────────────────────
//
// Source: `rtl8192ee/reg.h:93..104`.

/// `REG_HMETFR` — H2C mailbox transfer-finish register.  One bit per
/// mailbox; set to 1 by FW once it has consumed `HMEBOX_n`.
pub const REG_HMETFR: u64 = 0x01CC;

pub const REG_HMEBOX_0: u64 = 0x01D0;
pub const REG_HMEBOX_1: u64 = 0x01D4;
pub const REG_HMEBOX_2: u64 = 0x01D8;
pub const REG_HMEBOX_3: u64 = 0x01DC;

pub const REG_HMEBOX_EXT_0: u64 = 0x01F0;
pub const REG_HMEBOX_EXT_1: u64 = 0x01F4;
pub const REG_HMEBOX_EXT_2: u64 = 0x01F8;
pub const REG_HMEBOX_EXT_3: u64 = 0x01FC;

/// Number of mailboxes — round-robin modulus.
pub const H2C_BOX_COUNT: u8 = 4;

/// Mailbox numbers run 0..=3.
#[inline]
pub const fn box_reg(boxnum: u8) -> (u64, u64) {
    match boxnum & 0x03 {
        0 => (REG_HMEBOX_0, REG_HMEBOX_EXT_0),
        1 => (REG_HMEBOX_1, REG_HMEBOX_EXT_1),
        2 => (REG_HMEBOX_2, REG_HMEBOX_EXT_2),
        _ => (REG_HMEBOX_3, REG_HMEBOX_EXT_3),
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum H2cError {
    /// FW never cleared `REG_HMETFR` bit for the mailbox we tried to write.
    NotReady,
    /// `cmd_len > 7` — the mailbox + ext only carry 7 bytes total.
    PayloadTooLarge,
}

/// Returns `true` once FW has read (cleared) the mailbox indicated by
/// `boxnum`.  Mirrors `_rtl92ee_check_fw_read_last_h2c` (`fw.c:151`).
///
/// # Safety
/// Caller must own `mmio` (BAR0) exclusively.
pub unsafe fn fw_box_read(mmio: &MmioRegion, boxnum: u8) -> bool {
    // SAFETY: caller-asserted.
    let val = unsafe { mmio.read8(REG_HMETFR) };
    ((val >> (boxnum & 0x03)) & 0x01) == 0
}

/// Mailbox state — tracks which box to write next.  Linux holds this in
/// `rtl_hal::last_hmeboxnum` (`fw.c:224..342`).
#[derive(Copy, Clone, Debug, Default)]
pub struct H2cState {
    next_box: u8,
}

impl H2cState {
    pub const fn new() -> Self {
        Self { next_box: 0 }
    }

    #[inline]
    pub fn next(&self) -> u8 {
        self.next_box
    }
}

/// Wait for FW to free a mailbox, then write the H2C command.  Returns
/// the box number used.  After success the caller's `state` advances.
///
/// `cmd_buf` must be at most 7 bytes.  First byte goes into the
/// `HMEBOX_n + 0` lane after `element_id` is written into the box's
/// content[0].
///
/// # Safety
/// Caller must own `mmio` (BAR0) exclusively.
pub unsafe fn send_h2c(
    mmio: &MmioRegion,
    state: &mut H2cState,
    element_id: u8,
    cmd_buf: &[u8],
) -> Result<u8, H2cError> {
    if cmd_buf.len() > 7 {
        return Err(H2cError::PayloadTooLarge);
    }

    let boxnum = state.next_box & 0x03;
    let (box_reg, ext_reg) = box_reg(boxnum);

    // Poll up to ~10 ms for the box to be free.
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: caller-asserted.
            unsafe { fw_box_read(mmio, boxnum) }
        },
        Deadline::after_ms(10),
    );
    if !done {
        return Err(H2cError::NotReady);
    }

    // Compose the inline content + extension.
    let mut content = [0u8; 4];
    let mut ext = [0u8; 4];
    content[0] = element_id;

    // Linux puts up to 3 inline bytes at content[1..4]; cmd bytes >3 spill
    // into the extension box at `ext[0..(len-3)]`.  Pre-fill in the same
    // shape so a 7-byte command lays out 1 elem_id + 3 inline + 4 ext.
    let copy_inline = cmd_buf.len().min(3);
    content[1..(1 + copy_inline)].copy_from_slice(&cmd_buf[..copy_inline]);
    if cmd_buf.len() > 3 {
        let ext_len = cmd_buf.len() - 3;
        ext[..ext_len].copy_from_slice(&cmd_buf[3..]);
    }

    // SAFETY: caller-asserted.
    unsafe {
        // Linux writes ext first, then content, so FW sees the full
        // payload when it sees content[0] become non-zero.
        if cmd_buf.len() > 3 {
            for (i, b) in ext.iter().enumerate() {
                mmio.write8(ext_reg + i as u64, *b);
            }
        }
        for (i, b) in content.iter().enumerate() {
            mmio.write8(box_reg + i as u64, *b);
        }
    }

    state.next_box = (boxnum + 1) & 0x03;
    Ok(boxnum)
}

// ── FW download via REG_MCUFWDL + page-write ─────────────────────────────
//
// The firmware blob is delivered through `REG_MCUFWDL` page-write
// targeting the on-chip IMEM mailbox at offset 0x1000 (`START_ADDRESS`
// in Linux `efuse.c:12`).  The blob is split into 4-KiB pages
// (`FW_8192C_PAGE_SIZE`) and each page is written byte-by-byte through
// the BAR0 staging window.
//
// Source: `rtl8192ee/fw.c::rtl92ee_download_fw` (line 104).

/// FW image entry/staging address — the on-chip IMEM mailbox we POKE.
/// Linux `efuse.c:12::START_ADDRESS = 0x1000`.
pub const FW_START_ADDRESS: u64 = 0x1000;

/// Firmware-download page size.  `rtl8192ee/fw.h:10`.
pub const FW_PAGE_SIZE: usize = 4096;

/// `REG_MCUFWDL + 2` selects the active page register; the low 3 bits
/// are the page index, the upper 5 bits are reserved (preserved).
pub const REG_MCUFWDL_PAGE_SEL: u64 = REG_MCUFWDL + 2;

/// FW polling step (microseconds per iteration) and total iteration cap.
/// Linux `rtl8192ee/fw.h:11..12`.
pub const FW_POLL_DELAY_US: u64 = 5;
pub const FW_POLL_TIMEOUT_COUNT: u32 = 3000;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwDlError {
    /// FW checksum-report bit never came back.
    ChecksumTimeout,
    /// FW initialization-ready bit never came back after the 8051 reset.
    InitTimeout,
    /// Firmware blob too large.
    TooLarge,
}

/// Bits in `REG_MCUFWDL` checked by the FW-DL completion poll.
/// Source: `rtl8192ee/reg.h:881..886`.
pub const MCUFWDL_RDY: u32 = 1 << 1;
pub const FWDL_CHKSUM_RPT: u32 = 1 << 2;
pub const WINTINI_RDY: u32 = 1 << 6;

/// Enable / disable firmware download mode at `REG_MCUFWDL`.
/// Mirrors `_rtl92ee_enable_fw_download` (`fw.c:14`).
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn enable_fw_download(mmio: &MmioRegion, on: bool) {
    // SAFETY: caller-asserted.
    unsafe {
        if on {
            mmio.write8(REG_MCUFWDL, 0x05);
            let t = mmio.read8(REG_MCUFWDL + 2);
            mmio.write8(REG_MCUFWDL + 2, t & 0xF7);
        } else {
            let t = mmio.read8(REG_MCUFWDL);
            mmio.write8(REG_MCUFWDL, t & 0xFE);
        }
    }
}

/// Stream `data` (a single page worth, ≤4096 B) into the on-chip IMEM
/// mailbox at `START_ADDRESS`, after first selecting `page` via
/// `REG_MCUFWDL_PAGE_SEL`.  Mirrors `rtl_fw_page_write` (`efuse.c:1336`).
///
/// # Safety
/// Caller must own BAR0 exclusively; FW-DL must have been enabled.
pub unsafe fn write_fw_page(mmio: &MmioRegion, page: u32, data: &[u8]) {
    let page_idx = (page & 0x07) as u8;
    // SAFETY: caller-asserted.
    unsafe {
        let v = mmio.read8(REG_MCUFWDL_PAGE_SEL);
        mmio.write8(REG_MCUFWDL_PAGE_SEL, (v & 0xF8) | page_idx);
        // Block write: byte-by-byte into the FW-DL window at
        // `START_ADDRESS`.  Linux `rtl_fw_block_write` (efuse.c:1321).
        for (i, b) in data.iter().enumerate() {
            mmio.write8(FW_START_ADDRESS + i as u64, *b);
        }
    }
}

/// Poll `REG_MCUFWDL` until both the FW checksum-report bit
/// (`FWDL_CHKSUM_RPT`) is set, then assert `MCUFWDL_RDY`, then poll
/// for `WINTINI_RDY`.  Mirrors `_rtl92ee_fw_free_to_go` (`fw.c:63`).
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn poll_fw_ready(mmio: &MmioRegion) -> Result<(), FwDlError> {
    // Step 1: wait for checksum report.
    let chk_ok = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: caller-asserted.
            let v = unsafe { mmio.read32(REG_MCUFWDL) };
            v & FWDL_CHKSUM_RPT != 0
        },
        Deadline::after_ms(120),
    );
    if !chk_ok {
        return Err(FwDlError::ChecksumTimeout);
    }

    // Step 2: set MCUFWDL_RDY, clear WINTINI_RDY.
    // SAFETY: caller-asserted.
    unsafe {
        let mut v = mmio.read32(REG_MCUFWDL);
        v |= MCUFWDL_RDY;
        v &= !WINTINI_RDY;
        mmio.write32(REG_MCUFWDL, v);
    }

    // Step 3: 8051 self-reset (caller invokes [`firmware_selfreset`]
    // before reaching this point in the production flow; mirroring
    // Linux which inlines it).  We do it inline so the poll sequence
    // stays atomic.
    // SAFETY: caller-asserted.
    unsafe {
        let v = mmio.read8(REG_RSV_CTRL + 1);
        mmio.write8(REG_RSV_CTRL + 1, v & !0x01);
        let v = mmio.read8(REG_SYS_FUNC_EN + 1);
        mmio.write8(REG_SYS_FUNC_EN + 1, v & !0x04);
        narf_time::busy_wait_cycles(narf_time::ns_to_cycles(50 * 1_000));
        let v = mmio.read8(REG_RSV_CTRL + 1);
        mmio.write8(REG_RSV_CTRL + 1, v | 0x01);
        let v = mmio.read8(REG_SYS_FUNC_EN + 1);
        mmio.write8(REG_SYS_FUNC_EN + 1, v | 0x04);
    }

    // Step 4: poll for WINTINI_RDY.
    let init_ok = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: caller-asserted.
            let v = unsafe { mmio.read32(REG_MCUFWDL) };
            v & WINTINI_RDY != 0
        },
        Deadline::after_ms(300),
    );
    if !init_ok {
        return Err(FwDlError::InitTimeout);
    }
    Ok(())
}

/// Full firmware download.  Page-writes `fw_image` then polls
/// `REG_MCUFWDL` for `WINTINI_RDY`.  Mirrors `rtl92ee_download_fw`
/// (`fw.c:104`).
///
/// `fw_image` is the entire blob; the rtlwifi family discards the first
/// `sizeof(struct rtlwifi_firmware_header) == 32` bytes (the header)
/// when the signature indicates a header-bearing image.  Callers are
/// expected to slice the header off beforehand if needed.
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn download_fw(mmio: &MmioRegion, fw_image: &[u8]) -> Result<(), FwDlError> {
    // 8 × 4KiB = 32 KiB FW max.
    if fw_image.len() > 8 * FW_PAGE_SIZE {
        return Err(FwDlError::TooLarge);
    }

    // SAFETY: forwarded.
    unsafe {
        enable_fw_download(mmio, true);
    }

    let mut offset = 0;
    let mut page: u32 = 0;
    while offset + FW_PAGE_SIZE <= fw_image.len() {
        // SAFETY: forwarded.
        unsafe {
            write_fw_page(mmio, page, &fw_image[offset..offset + FW_PAGE_SIZE]);
        }
        offset += FW_PAGE_SIZE;
        page += 1;
    }
    if offset < fw_image.len() {
        // SAFETY: forwarded.
        unsafe {
            write_fw_page(mmio, page, &fw_image[offset..]);
        }
    }

    // SAFETY: forwarded.
    unsafe {
        enable_fw_download(mmio, false);
        poll_fw_ready(mmio)
    }
}
