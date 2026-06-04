//! MINIX superblock parsing.
//!
//! Clean-room. Layout derived from:
//! - Tanenbaum, *Operating Systems: Design and Implementation*
//!   (1st ed. 1987), Ch. 5 — defines the V1 superblock fields.
//! - Tanenbaum & Bos, *Modern Operating Systems* (4th ed. 2014),
//!   §4.6 — covers the V2/V3 extensions (`s_zones`, `s_block_size`).
//! - MINIX 3 Reference Manual on-disk-format documentation.
//!
//! The on-disk superblock occupies bytes 1024..1024+N of the volume
//! (N = sizeof of the version's struct, ≤ 28 bytes for V3). It is
//! read into a heap buffer of one logical block and decoded
//! field-by-field with `read_unaligned` u16/u32 helpers — no
//! `#[repr(C, packed)]` struct, because the struct varies by
//! version (V1 has `s_nzones`, V2/V3 use `s_zones` at offset 20).

use super::{MinixVersion, NameLen};

/// Magic numbers (Tanenbaum + MINIX-3 manual).
pub mod magic {
    pub const V1_14: u16 = 0x137F;
    pub const V1_30: u16 = 0x138F;
    pub const V2_14: u16 = 0x2468;
    pub const V2_30: u16 = 0x2478;
    pub const V3: u16 = 0x4D5A;
}

/// Decoded superblock — version-agnostic view used by the rest of
/// the driver. All sizes are in BYTES unless suffixed `_blocks` or
/// `_zones`.
#[derive(Debug, Copy, Clone)]
pub struct Superblock {
    pub version: MinixVersion,
    pub name_len: NameLen,
    /// Total inodes the volume can hold.
    pub ninodes: u32,
    /// Total zones in the volume (V1: `s_nzones`; V2/V3: `s_zones`).
    pub nzones: u32,
    /// Number of blocks occupied by the inode bitmap.
    pub imap_blocks: u32,
    /// Number of blocks occupied by the zone bitmap.
    pub zmap_blocks: u32,
    /// First data zone — zone numbers below this index are
    /// reserved for boot / superblock / bitmaps / inode table.
    pub first_data_zone: u32,
    /// log2(zone_size / block_size); always 0 in practice for V1/V2.
    pub log_zone_size: u8,
    /// Maximum file size (advisory).
    pub max_size: u32,
    /// Block size in bytes. V1/V2: hard-coded 1024. V3: read from
    /// the superblock at offset 24.
    pub block_size: u32,
}

impl Superblock {
    /// Decode a 1024-byte (or larger) buffer that contains the
    /// on-disk superblock starting at `byte_offset` within the
    /// buffer.
    ///
    /// Returns `None` if the magic is unrecognised.
    pub fn decode(buf: &[u8], byte_offset: usize) -> Option<Self> {
        // The smallest superblock layout we recognise (V1) reads
        // up to offset 18; V3 reads up to 26.
        if byte_offset + 28 > buf.len() {
            return None;
        }
        let s = &buf[byte_offset..];

        let read_u16 = |off: usize| -> u16 { u16::from_le_bytes([s[off], s[off + 1]]) };
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([s[off], s[off + 1], s[off + 2], s[off + 3]])
        };

        // Magic at offset 16 in every version.
        let m = read_u16(16);
        let (version, name_len) = match m {
            magic::V1_14 => (MinixVersion::V1, NameLen::N14),
            magic::V1_30 => (MinixVersion::V1, NameLen::N30),
            magic::V2_14 => (MinixVersion::V2, NameLen::N14),
            magic::V2_30 => (MinixVersion::V2, NameLen::N30),
            magic::V3 => (MinixVersion::V3, NameLen::N60),
            _ => return None,
        };

        let ninodes = read_u16(0) as u32;
        let imap_blocks = read_u16(4) as u32;
        let zmap_blocks = read_u16(6) as u32;
        let first_data_zone = read_u16(8) as u32;
        let log_zone_size = (read_u16(10) & 0xFF) as u8;
        let max_size = read_u32(12);

        let nzones = match version {
            MinixVersion::V1 => read_u16(2) as u32,
            MinixVersion::V2 | MinixVersion::V3 => read_u32(20),
        };

        let block_size = match version {
            MinixVersion::V1 | MinixVersion::V2 => 1024u32,
            MinixVersion::V3 => {
                let bs = read_u16(24) as u32;
                if bs == 0 {
                    1024
                } else {
                    bs
                }
            }
        };

        Some(Self {
            version,
            name_len,
            ninodes,
            nzones,
            imap_blocks,
            zmap_blocks,
            first_data_zone,
            log_zone_size,
            max_size,
            block_size,
        })
    }

    /// Zone size in bytes (= block_size << log_zone_size).
    pub fn zone_size(&self) -> u32 {
        self.block_size << self.log_zone_size as u32
    }

    /// Per-inode size on disk (V1: 32, V2/V3: 64).
    pub fn inode_size(&self) -> u32 {
        match self.version {
            MinixVersion::V1 => 32,
            MinixVersion::V2 | MinixVersion::V3 => 64,
        }
    }

    /// Number of inodes that fit in one block.
    pub fn inodes_per_block(&self) -> u32 {
        self.block_size / self.inode_size()
    }

    /// Number of blocks in the inode table — `ceil(ninodes / inodes_per_block)`.
    pub fn inode_table_blocks(&self) -> u32 {
        let ipb = self.inodes_per_block();
        self.ninodes.div_ceil(ipb)
    }

    /// First block of the inode bitmap (block 2 always — block 0 is
    /// the boot block and block 1 is the superblock).
    pub fn imap_first_block(&self) -> u32 {
        2
    }

    pub fn zmap_first_block(&self) -> u32 {
        self.imap_first_block() + self.imap_blocks
    }

    pub fn inode_table_first_block(&self) -> u32 {
        self.zmap_first_block() + self.zmap_blocks
    }

    /// Block (relative to start of volume) and byte offset within
    /// that block for inode number `ino` (1-based; inode 0 is
    /// reserved).
    pub fn inode_location(&self, ino: u32) -> Option<(u32, u32)> {
        if ino == 0 || ino > self.ninodes {
            return None;
        }
        let zero_based = ino - 1;
        let ipb = self.inodes_per_block();
        let block = self.inode_table_first_block() + zero_based / ipb;
        let off = (zero_based % ipb) * self.inode_size();
        Some((block, off))
    }

    /// Zone-pointer fan-out per block, in *zone numbers*. V1 uses
    /// u16 pointers, V2/V3 use u32 pointers.
    pub fn zone_ptrs_per_block(&self) -> u32 {
        match self.version {
            MinixVersion::V1 => self.block_size / 2,
            MinixVersion::V2 | MinixVersion::V3 => self.block_size / 4,
        }
    }

    pub fn zone_ptr_size(&self) -> usize {
        match self.version {
            MinixVersion::V1 => 2,
            MinixVersion::V2 | MinixVersion::V3 => 4,
        }
    }
}
