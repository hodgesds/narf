//! Lazily initialized block groups (`uninit_bg`, with `metadata_csum`).
//!
//! mke2fs leaves the bitmaps of groups nothing uses unwritten and says so in
//! the group descriptor: `EXT4_BG_BLOCK_UNINIT` (the block bitmap is
//! whatever the group's layout implies), `EXT4_BG_INODE_UNINIT` (every inode
//! is free). On a large disk that is most groups. The on-disk bitmap of such
//! a group is garbage, so it is never read. It is computed here as Linux
//! computes it (`fs/ext4/balloc.c::ext4_init_block_bitmap`,
//! `ext4_num_base_meta_blocks`, `ext4_bg_has_super`, `ext4_bg_num_gdb`;
//! `fs/ext4/ialloc.c::ext4_read_inode_bitmap`), and written out, with the
//! flag cleared, by the first allocation in the group.
//!
//! `meta_bg` and `bigalloc` are refused at mount, so a cluster is a block
//! and the descriptor table is contiguous after each superblock copy.

use alloc::vec;
use alloc::vec::Vec;

use super::super::group_desc::GroupDesc;
use super::super::superblock::{compat, ro_compat, Superblock};

/// Whether flag bits in group descriptors mean anything: only with a
/// descriptor checksum (`ext4_has_group_desc_csum`).
pub(crate) fn has_group_desc_csum(sb: &Superblock) -> bool {
    sb.feature_ro_compat & (ro_compat::METADATA_CSUM | ro_compat::GDT_CSUM) != 0
}

/// `test_root(a, b)`: `a` is a power of `b`.
fn is_power_of(mut a: u32, b: u32) -> bool {
    loop {
        if a < b {
            return false;
        }
        if a == b {
            return true;
        }
        if a % b != 0 {
            return false;
        }
        a /= b;
    }
}

/// `ext4_bg_has_super`: whether `group` holds a superblock copy.
pub(crate) fn has_super(sb: &Superblock, group: u32) -> bool {
    if group == 0 {
        return true;
    }
    if sb.feature_compat & compat::SPARSE_SUPER2 != 0 {
        return group == sb.backup_bgs[0] || group == sb.backup_bgs[1];
    }
    if group <= 1 || sb.feature_ro_compat & ro_compat::SPARSE_SUPER == 0 {
        return true;
    }
    if group & 1 == 0 {
        return false;
    }
    is_power_of(group, 3) || is_power_of(group, 5) || is_power_of(group, 7)
}

/// `s_gdb_count`: blocks of the group-descriptor table.
pub(crate) fn gdt_blocks(sb: &Superblock) -> u32 {
    let per_block = sb.block_size() as usize / sb.effective_desc_size();
    (sb.block_group_count() as usize).div_ceil(per_block) as u32
}

/// `ext4_num_base_meta_blocks` without `meta_bg`: the superblock copy, the
/// descriptor table and its reserved growth, in a group with a copy.
pub(crate) fn base_meta_blocks(sb: &Superblock, group: u32) -> u32 {
    if has_super(sb, group) {
        1 + gdt_blocks(sb) + u32::from(sb.reserved_gdt_blocks)
    } else {
        0
    }
}

/// First block of `group`.
pub(crate) fn group_first_block(sb: &Superblock, group: u32) -> u64 {
    u64::from(sb.first_data_block) + u64::from(group) * u64::from(sb.blocks_per_group)
}

/// `num_clusters_in_group`: the last group may be short.
pub(crate) fn blocks_in_group(sb: &Superblock, group: u32) -> u32 {
    let first = group_first_block(sb, group);
    let end = (first + u64::from(sb.blocks_per_group)).min(sb.total_blocks());
    end.saturating_sub(first) as u32
}

/// `s_itb_per_group`: blocks of one group's inode table.
pub(crate) fn inode_table_blocks(sb: &Superblock) -> u32 {
    (sb.inodes_per_group as usize * sb.inode_size_bytes()).div_ceil(sb.block_size() as usize) as u32
}

fn set_bit(bitmap: &mut [u8], bit: usize) {
    bitmap[bit / 8] |= 1 << (bit % 8);
}

/// `ext4_mark_bitmap_end`: bits past the group's last block or inode are
/// set, so they never look free.
fn mark_end(bitmap: &mut [u8], used: usize) {
    for bit in used..bitmap.len() * 8 {
        set_bit(bitmap, bit);
    }
}

/// `ext4_init_block_bitmap`: the block bitmap of a `BLOCK_UNINIT` group, as
/// one block. `None` when the layout cannot fit the bitmap (corrupt).
pub(crate) fn init_block_bitmap(sb: &Superblock, group: u32, gd: &GroupDesc) -> Option<Vec<u8>> {
    let bs = sb.block_size() as usize;
    let mut bitmap = vec![0u8; bs];
    let base = base_meta_blocks(sb, group) as usize;
    if base / 8 >= bs {
        return None;
    }
    for bit in 0..base {
        set_bit(&mut bitmap, bit);
    }
    let first = group_first_block(sb, group);
    let size = u64::from(blocks_in_group(sb, group));
    let mut mark = |block: u64| {
        if block >= first && block < first + size {
            set_bit(&mut bitmap, (block - first) as usize);
        }
    };
    mark(gd.block_bitmap);
    mark(gd.inode_bitmap);
    for block in gd.inode_table..gd.inode_table + u64::from(inode_table_blocks(sb)) {
        mark(block);
    }
    mark_end(&mut bitmap, size as usize);
    Some(bitmap)
}

/// The inode bitmap of an `INODE_UNINIT` group: every inode free, the bits
/// past `s_inodes_per_group` set.
pub(crate) fn init_inode_bitmap(sb: &Superblock) -> Vec<u8> {
    let mut bitmap = vec![0u8; sb.block_size() as usize];
    mark_end(&mut bitmap, sb.inodes_per_group as usize);
    bitmap
}

/// Clear bits among the first `bits` of `bitmap`.
pub(crate) fn free_bits(bitmap: &[u8], bits: u32) -> u32 {
    (0..bits as usize)
        .filter(|&bit| bitmap[bit / 8] & (1 << (bit % 8)) == 0)
        .count() as u32
}
