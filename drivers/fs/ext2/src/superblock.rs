//! ext2 superblock layout.
//!
//! Sources:
//! - Card, Ts'o, Tweedie. _Design and Implementation of the Second
//!   Extended Filesystem_, §"Physical Layout".
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_,
//!   §"Superblock".
//! - OSDev Wiki, "Ext2 — Superblock":
//!   <https://wiki.osdev.org/Ext2#Superblock>
//!
//! No Linux/GRUB/e2fsprogs source was consulted; the field offsets
//! below come from the OSDev wiki + Rusling cross-check.

use super::EXT2_SUPER_MAGIC;

/// Decoded ext2 superblock — the subset of fields this driver
/// actually uses. We deliberately do _not_ use `#[repr(C, packed)]`
/// for the full 1024-byte super-block because we only need a dozen
/// fields and reading them with `u32::from_le_bytes` is cheaper /
/// less unsafe than a full layout struct.
#[derive(Debug, Copy, Clone)]
pub struct Superblock {
    /// `s_inodes_count` — total inodes in the volume.
    pub inodes_count: u32,
    /// `s_blocks_count` — total blocks in the volume.
    pub blocks_count: u32,
    /// `s_first_data_block` — block number of group 0's superblock.
    /// Equals 1 on 1-KiB block volumes (the boot sector + superblock
    /// share block 0 only on >= 2-KiB-block volumes); equals 0 on
    /// 2 KiB / 4 KiB block volumes (superblock starts at byte 1024 of
    /// block 0). The block-group descriptor table sits in the block
    /// _after_ this one.
    pub first_data_block: u32,
    /// `s_log_block_size` — block size = 1024 << s_log_block_size.
    pub log_block_size: u32,
    /// `s_blocks_per_group`.
    pub blocks_per_group: u32,
    /// `s_inodes_per_group`.
    pub inodes_per_group: u32,
    /// `s_magic` — must be `0xEF53` for a valid ext2 volume.
    pub magic: u16,
    /// `s_rev_level` — 0 = good-old, 1 = dynamic. Determines whether
    /// `s_inode_size` is meaningful.
    pub rev_level: u32,
    /// `s_inode_size` — bytes per inode. Fixed at 128 on rev-0
    /// volumes; on rev-1 the field is meaningful and may be 256+.
    pub inode_size: u16,
}

impl Superblock {
    /// Decode a superblock from a 1024-byte (or larger) buffer
    /// containing the superblock's bytes starting at byte 0.
    /// Returns `None` if the magic is wrong.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 96 {
            return None;
        }
        let magic = u16::from_le_bytes([buf[56], buf[57]]);
        if magic != EXT2_SUPER_MAGIC {
            return None;
        }

        let inodes_count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let blocks_count = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let first_data_block = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let log_block_size = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let blocks_per_group = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let inodes_per_group = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
        let rev_level = u32::from_le_bytes([buf[76], buf[77], buf[78], buf[79]]);
        let inode_size = if rev_level >= 1 {
            u16::from_le_bytes([buf[88], buf[89]])
        } else {
            128
        };

        Some(Self {
            inodes_count,
            blocks_count,
            first_data_block,
            log_block_size,
            blocks_per_group,
            inodes_per_group,
            magic,
            rev_level,
            inode_size,
        })
    }

    /// Block size in bytes — `1024 << s_log_block_size`. The minimum
    /// is 1024 (with `s_log_block_size == 0`).
    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }

    /// Number of block groups in the volume — ceil(blocks_count /
    /// blocks_per_group).
    pub fn block_group_count(&self) -> u32 {
        (self.blocks_count + self.blocks_per_group - 1) / self.blocks_per_group
    }

    /// Bytes per inode — for rev-0 volumes this is fixed at 128;
    /// rev-1+ uses the explicit `s_inode_size`.
    pub fn inode_size_bytes(&self) -> usize {
        self.inode_size as usize
    }
}
