//! Realtek RTSX host-command-buffer engine.
//!
//! The RTSX command engine is a simple FIFO of 4-byte entries that are
//! written to a DMA-coherent page and dispatched by writing the entry
//! count to HCBCTLR.  Each 32-bit entry is:
//!
//! ```text
//!  [31:30] type  — 0=READ, 1=WRITE, 2=CHECK
//!  [29:16] addr  — 14-bit internal register address
//!  [15:8]  mask  — write mask (only bits set here are updated)
//!  [7:0]   data  — data byte
//! ```
//!
//! Reference: Linux `include/linux/rtsx_pci.h` `rtsx_pci_add_cmd`
//! inline, and `drivers/misc/cardreader/rtsx_pcr.c`
//! `rtsx_pci_send_cmd`.

use super::regs::{CHECK_REG_CMD, READ_REG_CMD, WRITE_REG_CMD};

/// Maximum entries in a single command batch (256 × 4 bytes = 1 KiB).
/// The real hardware supports 256; we stay conservative.
pub const CMD_BUF_ENTRIES: usize = 256;

/// One 4-byte command entry.
#[derive(Copy, Clone, Debug)]
pub struct CmdEntry(pub u32);

impl CmdEntry {
    /// Build a WRITE_REG command: write `data` (masked by `mask`) into
    /// internal register `addr`.
    ///
    /// Layout per Linux `rtsx_pci_add_cmd`:
    ///   bits[31:30] = type << 30
    ///   bits[29:16] = addr
    ///   bits[15:8]  = mask
    ///   bits[7:0]   = data
    #[inline]
    pub fn write(addr: u16, mask: u8, data: u8) -> Self {
        let word = ((WRITE_REG_CMD as u32) << 30)
            | ((addr as u32 & 0x3FFF) << 16)
            | ((mask as u32) << 8)
            | (data as u32);
        CmdEntry(word)
    }

    /// Build a READ_REG command: read internal register `addr`.
    /// The result appears in the command-buffer response slot after the
    /// batch completes.
    #[inline]
    pub fn read(addr: u16) -> Self {
        let word = ((READ_REG_CMD as u32) << 30)
            | ((addr as u32 & 0x3FFF) << 16);
        CmdEntry(word)
    }

    /// Build a CHECK_REG command: stall the engine until
    /// `(reg & mask) == data`.  Used to poll the SD_CMD_STATE register.
    #[inline]
    pub fn check(addr: u16, mask: u8, data: u8) -> Self {
        let word = ((CHECK_REG_CMD as u32) << 30)
            | ((addr as u32 & 0x3FFF) << 16)
            | ((mask as u32) << 8)
            | (data as u32);
        CmdEntry(word)
    }

    /// Raw 32-bit little-endian encoding for DMA.
    #[inline]
    pub fn as_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

/// A batch of commands assembled before dispatch.
///
/// The caller fills entries via `push_write` / `push_read` etc., then
/// calls `Rtsx::dispatch_cmd_buf` which DMA-maps the entries, writes
/// the physical address to HCBAR, and triggers the engine.
#[derive(Debug)]
pub struct CmdBuf {
    entries: [CmdEntry; CMD_BUF_ENTRIES],
    len: usize,
}

impl CmdBuf {
    /// Create an empty buffer.
    pub const fn new() -> Self {
        CmdBuf {
            entries: [CmdEntry(0); CMD_BUF_ENTRIES],
            len: 0,
        }
    }

    /// Reset for reuse.
    #[inline]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Number of entries currently in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Append one entry. Returns `false` if the buffer is full.
    #[inline]
    pub fn push(&mut self, e: CmdEntry) -> bool {
        if self.len >= CMD_BUF_ENTRIES {
            return false;
        }
        self.entries[self.len] = e;
        self.len += 1;
        true
    }

    /// Convenience: append a WRITE_REG entry.
    #[inline]
    pub fn push_write(&mut self, addr: u16, mask: u8, data: u8) -> bool {
        self.push(CmdEntry::write(addr, mask, data))
    }

    /// Convenience: append a READ_REG entry.
    #[inline]
    pub fn push_read(&mut self, addr: u16) -> bool {
        self.push(CmdEntry::read(addr))
    }

    /// Convenience: append a CHECK_REG entry.
    #[inline]
    pub fn push_check(&mut self, addr: u16, mask: u8, data: u8) -> bool {
        self.push(CmdEntry::check(addr, mask, data))
    }

    /// Serialise all entries into a flat byte slice suitable for DMA.
    /// `out` must be at least `self.len() * 4` bytes.
    pub fn serialise(&self, out: &mut [u8]) {
        for (i, e) in self.entries[..self.len].iter().enumerate() {
            let b = e.as_le_bytes();
            out[i * 4..i * 4 + 4].copy_from_slice(&b);
        }
    }
}

/// Build the 6-byte SD command frame written into SD_CMD0..SD_CMD5.
///
/// SD Physical Layer Simplified Spec v8.00 §7.3.1: the command frame
/// is 48 bits = start(1) | direction(1) | command_index(6) |
/// argument(32) | CRC7(7) | end(1).  The RTSX engine fills CRC7; the
/// host provides the 6 bytes as:
///   CMD0[5:0] = command_index (without start/direction bits)
///   CMD1..CMD4 = argument[31:0] big-endian
///   CMD5 = CRC7 (hardware fills this; set to 0)
#[inline]
pub fn build_sd_cmd_frame(cmd_index: u8, arg: u32) -> [u8; 6] {
    [
        0x40 | (cmd_index & 0x3F), // start=0, direction=1 (host-to-card), index
        ((arg >> 24) & 0xFF) as u8,
        ((arg >> 16) & 0xFF) as u8,
        ((arg >> 8) & 0xFF) as u8,
        (arg & 0xFF) as u8,
        0x00, // CRC7 — filled by hardware
    ]
}
