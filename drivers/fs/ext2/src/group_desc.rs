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

/// One block group descriptor, 32 bytes on disk.
#[derive(Debug, Copy, Clone)]
pub struct GroupDesc {
    /// `bg_block_bitmap` — block holding the block bitmap.
    pub block_bitmap: u32,
    /// `bg_inode_bitmap` — block holding the inode bitmap.
    pub inode_bitmap: u32,
    /// `bg_inode_table` — first block of the inode table.
    pub inode_table: u32,
    /// `bg_free_blocks_count`.
    pub free_blocks_count: u16,
    /// `bg_free_inodes_count`.
    pub free_inodes_count: u16,
    /// `bg_used_dirs_count`.
    pub used_dirs_count: u16,
}

/// Each on-disk descriptor is 32 bytes (the design-paper layout; the
/// trailing 14 bytes are the `bg_pad` + `bg_reserved[3 * u32]`).
pub const GROUP_DESC_SIZE: usize = 32;

impl GroupDesc {
    /// Decode a single descriptor from a 32-byte slice.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < GROUP_DESC_SIZE {
            return None;
        }
        Some(Self {
            block_bitmap: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            inode_bitmap: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            inode_table: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            free_blocks_count: u16::from_le_bytes([buf[12], buf[13]]),
            free_inodes_count: u16::from_le_bytes([buf[14], buf[15]]),
            used_dirs_count: u16::from_le_bytes([buf[16], buf[17]]),
        })
    }
}
