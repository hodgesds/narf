//! ext2 block group descriptor.
//!
//! Sources:
//! - Card, Ts'o, Tweedie, §"Block Groups" — overview.
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_,
//!   §"Group Descriptor".
//! - OSDev Wiki, "Ext2 — Block Group Descriptor":
//!   <https://wiki.osdev.org/Ext2#Block_Group_Descriptor>
//!
//! No GPL/LGPL source was consulted; offsets/sizes below come from
//! the wiki + Rusling.

/// One block group descriptor. 32 bytes on ext2/3, 64 bytes on
/// ext4 with the `64BIT` incompat feature (in which case the
/// 32-bit fields gain a `_hi` companion to extend block addresses
/// past 4 GiB).
#[derive(Debug, Copy, Clone)]
pub struct GroupDesc {
    /// `bg_block_bitmap` (low 32) + `bg_block_bitmap_hi` (high 32
    /// when 64BIT) — block holding the block bitmap.
    pub block_bitmap: u64,
    /// `bg_inode_bitmap` (+ _hi) — block holding the inode bitmap.
    pub inode_bitmap: u64,
    /// `bg_inode_table` (+ _hi) — first block of the inode table.
    pub inode_table: u64,
    /// `bg_free_blocks_count` (+ _hi).
    pub free_blocks_count: u32,
    /// `bg_free_inodes_count` (+ _hi).
    pub free_inodes_count: u32,
    /// `bg_used_dirs_count` (+ _hi).
    pub used_dirs_count: u32,
}

/// ext2/3 on-disk descriptor size. ext4 with 64BIT uses 64.
pub const GROUP_DESC_SIZE: usize = 32;
pub const GROUP_DESC_SIZE_64BIT: usize = 64;

impl GroupDesc {
    /// Decode a single descriptor. Pass `desc_size = 32` for ext2/3,
    /// `desc_size = 64` for ext4 with 64BIT incompat feature
    /// (resolved via `Superblock::effective_desc_size`).
    pub fn parse_sized(buf: &[u8], desc_size: usize) -> Option<Self> {
        if buf.len() < desc_size || desc_size < GROUP_DESC_SIZE {
            return None;
        }
        let block_bitmap_lo = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let inode_bitmap_lo = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let inode_table_lo = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let free_blocks_lo = u16::from_le_bytes([buf[12], buf[13]]);
        let free_inodes_lo = u16::from_le_bytes([buf[14], buf[15]]);
        let used_dirs_lo = u16::from_le_bytes([buf[16], buf[17]]);

        let (
            block_bitmap_hi,
            inode_bitmap_hi,
            inode_table_hi,
            free_blocks_hi,
            free_inodes_hi,
            used_dirs_hi,
        ) = if desc_size >= 64 {
            // ext4 64BIT layout — _hi fields at offsets 32..52.
            //   32..36 block_bitmap_hi  (u32)
            //   36..40 inode_bitmap_hi
            //   40..44 inode_table_hi
            //   44..46 free_blocks_count_hi (u16)
            //   46..48 free_inodes_count_hi
            //   48..50 used_dirs_count_hi
            (
                u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]),
                u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
                u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]),
                u16::from_le_bytes([buf[44], buf[45]]),
                u16::from_le_bytes([buf[46], buf[47]]),
                u16::from_le_bytes([buf[48], buf[49]]),
            )
        } else {
            (0, 0, 0, 0, 0, 0)
        };

        Some(Self {
            block_bitmap: ((block_bitmap_hi as u64) << 32) | block_bitmap_lo as u64,
            inode_bitmap: ((inode_bitmap_hi as u64) << 32) | inode_bitmap_lo as u64,
            inode_table: ((inode_table_hi as u64) << 32) | inode_table_lo as u64,
            free_blocks_count: ((free_blocks_hi as u32) << 16) | free_blocks_lo as u32,
            free_inodes_count: ((free_inodes_hi as u32) << 16) | free_inodes_lo as u32,
            used_dirs_count: ((used_dirs_hi as u32) << 16) | used_dirs_lo as u32,
        })
    }

    /// Convenience: parse a 32-byte ext2/3 descriptor. For ext4
    /// volumes with 64BIT, callers MUST use `parse_sized(buf, 64)`
    /// or they'll silently ignore the high 32 bits of every
    /// block address.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        Self::parse_sized(buf, GROUP_DESC_SIZE)
    }
}
