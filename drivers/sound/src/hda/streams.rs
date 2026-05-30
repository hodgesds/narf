//! Stream descriptors + Buffer Descriptor List (BDL).
//!
//! HDA §3.3.41 (per-stream registers) and §3.6.2 (BDL layout).
//!
//! Each HDA stream descriptor exposes:
//!
//! ```text
//!   SDxCTL    +0x00  24-bit control (RUN, SRST, IOCE, FEIE, DEIE, STRM)
//!   SDxSTS    +0x03  status (BCIS, FIFOE, DESE)
//!   SDxLPIB   +0x04  link position in current buffer
//!   SDxCBL    +0x08  cyclic buffer length (in bytes)
//!   SDxLVI    +0x0C  last valid index (BDL entry count - 1)
//!   SDxFIFOS  +0x10  FIFO size (R/O, codec-link-dependent)
//!   SDxFMT    +0x12  stream format (see crate::format::pack_sdfmt)
//!   SDxBDPL   +0x18  BDL base low
//!   SDxBDPU   +0x1C  BDL base high
//! ```
//!
//! The BDL itself is an array of 16-byte entries:
//!
//! ```text
//!   bytes  0..7  buffer address (64-bit physical)
//!   bytes  8..11 buffer length in bytes
//!   bytes 12..15 flags (bit 0 = IOC — Interrupt On Completion)
//! ```
//!
//! Linux references:
//! - `sound/hda/core/controller.c::snd_hdac_stream_setup_periods`
//!   for BDL builder.
//! - `sound/hda/core/controller.c::snd_hdac_stream_start` for
//!   SDxCTL.RUN.

// ── SDxCTL bits ─────────────────────────────────────────────────────

/// Stream reset (drive 1, wait, then clear).
pub const SDCTL_SRST: u32 = 1 << 0;
/// Stream run — set to start DMA.
pub const SDCTL_RUN: u32 = 1 << 1;
/// Interrupt on completion enable (per-buffer IRQ from BDL IOC bit).
pub const SDCTL_IOCE: u32 = 1 << 2;
/// FIFO error interrupt enable.
pub const SDCTL_FEIE: u32 = 1 << 3;
/// Descriptor error interrupt enable.
pub const SDCTL_DEIE: u32 = 1 << 4;

/// Stream tag (bits 20..23). Codec sees this tag in its converter
/// stream/channel verb pair.
pub const SDCTL_STRM_SHIFT: u32 = 20;

// ── SDxSTS bits ─────────────────────────────────────────────────────

/// Buffer completion interrupt status (W1C).
pub const SDSTS_BCIS: u8 = 1 << 2;
/// FIFO error (W1C).
pub const SDSTS_FIFOE: u8 = 1 << 3;
/// Descriptor error (W1C).
pub const SDSTS_DESE: u8 = 1 << 4;
/// FIFO ready (read-only).
pub const SDSTS_FIFORDY: u8 = 1 << 5;

/// One BDL entry — 16 bytes. Lays out exactly as HDA §3.6.2 expects.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(C, packed)]
pub struct BdlEntry {
    /// Buffer physical address.
    pub addr: u64,
    /// Buffer length in bytes.
    pub length: u32,
    /// Flags. Bit 0 = IOC (Interrupt On Completion). Remaining bits
    /// must be zero.
    pub flags: u32,
}

impl BdlEntry {
    pub const fn new(addr: u64, length: u32, ioc: bool) -> Self {
        BdlEntry { addr, length, flags: if ioc { 1 } else { 0 } }
    }

    /// Serialise the entry as the 4-word little-endian image HW reads.
    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        let addr = self.addr.to_le_bytes();
        let length = self.length.to_le_bytes();
        let flags = self.flags.to_le_bytes();
        out[0..8].copy_from_slice(&addr);
        out[8..12].copy_from_slice(&length);
        out[12..16].copy_from_slice(&flags);
        out
    }

    /// Decode a 16-byte BDL entry image.
    pub fn from_le_bytes(b: &[u8; 16]) -> Self {
        let mut addr = [0u8; 8];
        addr.copy_from_slice(&b[0..8]);
        let mut length = [0u8; 4];
        length.copy_from_slice(&b[8..12]);
        let mut flags = [0u8; 4];
        flags.copy_from_slice(&b[12..16]);
        BdlEntry {
            addr: u64::from_le_bytes(addr),
            length: u32::from_le_bytes(length),
            flags: u32::from_le_bytes(flags),
        }
    }
}

/// Stream-slot allocator state. The controller tracks one slot per
/// stream descriptor; output/input/bidir are distinguished here.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StreamSlot {
    /// Free output stream.
    FreeOutput,
    /// Free input stream.
    FreeInput,
    /// Free bidir stream.
    FreeBidir,
    /// Taken — output.
    TakenOutput,
    /// Taken — input.
    TakenInput,
    /// Taken — bidir.
    TakenBidir,
}

/// A handle naming a single stream descriptor. Carries the byte
/// offset into the controller's BAR0 plus the direction.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StreamDescriptor {
    /// Byte offset of the descriptor block in BAR0 (e.g. 0x80 + 0x20*N).
    pub offset: u64,
    /// True if this is an input (capture) stream.
    pub is_input: bool,
}

impl StreamDescriptor {
    /// Build the SDxCTL value to start the stream at the given tag.
    pub const fn ctl_start(tag: u8) -> u32 {
        SDCTL_RUN | SDCTL_IOCE | SDCTL_FEIE | SDCTL_DEIE
            | ((tag as u32 & 0xF) << SDCTL_STRM_SHIFT)
    }

    /// Build the SDxCTL value to clear RUN while leaving tag /
    /// IRQ-enable bits in place — used by `trigger_stop`.
    pub const fn ctl_stop(tag: u8) -> u32 {
        SDCTL_IOCE | SDCTL_FEIE | SDCTL_DEIE
            | ((tag as u32 & 0xF) << SDCTL_STRM_SHIFT)
    }

    /// Build the SDxCTL value that drives stream reset (SRST=1).
    pub const fn ctl_reset() -> u32 {
        SDCTL_SRST
    }
}
