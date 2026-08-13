//! ext4 metadata-checksum primitives.
//!
//! `metadata_csum` uses CRC32C.  `csum_seed` changes only the seed used
//! for that checksum: the seed is stored in the superblock instead of being
//! derived from the filesystem UUID.  The seed does not change any ext4
//! on-disk structure, but accepting it without checksum handling would let a
//! writer silently leave stale metadata checksums behind.

use super::superblock::Superblock;

/// Reversed Castagnoli polynomial used by CRC32C in reflected form.
const CRC32C_POLY: u32 = 0x82f6_3b78;

/// Offset of `s_checksum` in the 1024-byte ext4 superblock.
const SUPERBLOCK_CHECKSUM_OFFSET: usize = 0x3fc;

/// `i_generation` in an ext4 inode.  It is part of every inode-, directory-,
/// and extent-block checksum namespace.
const INODE_GENERATION_OFFSET: usize = 0x64;
/// Low 16 bits of an inode checksum (`l_i_checksum_lo` in `i_osd2`).
const INODE_CHECKSUM_LO_OFFSET: usize = 0x7c;
/// High 16 bits of an inode checksum (`i_checksum_hi`).
const INODE_CHECKSUM_HI_OFFSET: usize = 0x82;
/// `i_extra_isize`; it tells us which extended inode fields are valid.
const INODE_EXTRA_ISIZE_OFFSET: usize = 0x80;
/// `bg_checksum` in an ext4 group descriptor.
const GROUP_DESC_CHECKSUM_OFFSET: usize = 0x1e;

/// CRC32C update with the same seed-chaining convention ext4 uses.
///
/// Callers supply the running state directly: a UUID-derived seed is
/// `crc32c(!0, uuid)`, while a `csum_seed` filesystem supplies the stored
/// `s_checksum_seed` value.  There is deliberately no final xor.
pub fn crc32c(mut state: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        state ^= byte as u32;
        for _ in 0..8 {
            state = if state & 1 != 0 {
                (state >> 1) ^ CRC32C_POLY
            } else {
                state >> 1
            };
        }
    }
    state
}

/// Seed to use for ext4 metadata checksums on `sb`.
pub fn seed(sb: &Superblock) -> u32 {
    if sb.uses_csum_seed() {
        sb.checksum_seed
    } else {
        crc32c(!0, &sb.uuid)
    }
}

/// Verify the ext4 superblock checksum.
///
/// The superblock is the exception to the `csum_seed` rule: ext4 calculates
/// this one from the fixed `!0` seed. The checksum field itself is excluded
/// from the calculation; its stored little-endian value covers the fixed
/// 1024-byte superblock prefix.
pub fn verify_superblock(sb: &Superblock, bytes: &[u8]) -> bool {
    if !sb.has_metadata_csum() || bytes.len() < SUPERBLOCK_CHECKSUM_OFFSET + 4 {
        return true;
    }
    let stored = u32::from_le_bytes(
        bytes[SUPERBLOCK_CHECKSUM_OFFSET..SUPERBLOCK_CHECKSUM_OFFSET + 4]
            .try_into()
            .expect("superblock checksum slice is four bytes"),
    );
    crc32c(!0, &bytes[..SUPERBLOCK_CHECKSUM_OFFSET]) == stored
}

/// Recompute `s_checksum` after mutating the primary superblock.
pub fn write_superblock_checksum(sb: &Superblock, bytes: &mut [u8]) -> Option<()> {
    if !sb.has_metadata_csum() {
        return Some(());
    }
    if bytes.len() < SUPERBLOCK_CHECKSUM_OFFSET + 4 {
        return None;
    }
    let checksum = crc32c(!0, &bytes[..SUPERBLOCK_CHECKSUM_OFFSET]);
    bytes[SUPERBLOCK_CHECKSUM_OFFSET..SUPERBLOCK_CHECKSUM_OFFSET + 4]
        .copy_from_slice(&checksum.to_le_bytes());
    Some(())
}

/// Calculate the full checksum for one on-disk inode.
///
/// The inode number and generation make a copied inode record fail checksum
/// validation in a different slot. Both checksum fields are logically zero
/// while hashing; callers can use [`write_inode_checksum`] to install the
/// resulting low and high halves into an encoded inode record.
pub fn inode_checksum(sb: &Superblock, inode_no: u32, inode: &[u8]) -> Option<u32> {
    if !sb.has_metadata_csum() || inode.len() < 128 {
        return None;
    }
    let generation = inode.get(INODE_GENERATION_OFFSET..INODE_GENERATION_OFFSET + 4)?;
    let mut state = crc32c(seed(sb), &inode_no.to_le_bytes());
    state = crc32c(state, generation);

    // The original 128-byte inode always has the low checksum field. The
    // high field exists only when the inode's `i_extra_isize` reaches it;
    // a larger inode slot may instead use the bytes for an older layout.
    state = crc32c(state, &inode[..INODE_CHECKSUM_LO_OFFSET]);
    state = crc32c(state, &[0, 0]);
    let after_low = INODE_CHECKSUM_LO_OFFSET + 2;
    let has_high = inode.len() >= INODE_CHECKSUM_HI_OFFSET + 2
        && inode.len() >= INODE_EXTRA_ISIZE_OFFSET + 2
        && u16::from_le_bytes([
            inode[INODE_EXTRA_ISIZE_OFFSET],
            inode[INODE_EXTRA_ISIZE_OFFSET + 1],
        ]) >= 4;
    if !has_high {
        return Some(crc32c(state, &inode[after_low..]));
    }
    state = crc32c(state, &inode[after_low..INODE_CHECKSUM_HI_OFFSET]);
    state = crc32c(state, &[0, 0]);
    Some(crc32c(state, &inode[INODE_CHECKSUM_HI_OFFSET + 2..]))
}

/// Update the checksum fields of an encoded inode in place.
pub fn write_inode_checksum(sb: &Superblock, inode_no: u32, inode: &mut [u8]) -> Option<()> {
    let checksum = inode_checksum(sb, inode_no, inode)?;
    inode[INODE_CHECKSUM_LO_OFFSET..INODE_CHECKSUM_LO_OFFSET + 2]
        .copy_from_slice(&(checksum as u16).to_le_bytes());
    let has_high = inode.len() >= INODE_CHECKSUM_HI_OFFSET + 2
        && inode.len() >= INODE_EXTRA_ISIZE_OFFSET + 2
        && u16::from_le_bytes([
            inode[INODE_EXTRA_ISIZE_OFFSET],
            inode[INODE_EXTRA_ISIZE_OFFSET + 1],
        ]) >= 4;
    if has_high {
        inode[INODE_CHECKSUM_HI_OFFSET..INODE_CHECKSUM_HI_OFFSET + 2]
            .copy_from_slice(&((checksum >> 16) as u16).to_le_bytes());
    }
    Some(())
}

/// Verify the stored inode checksum, accepting 128-byte and old extended
/// inodes that legally carry only the low 16 bits.
pub fn verify_inode_checksum(sb: &Superblock, inode_no: u32, inode: &[u8]) -> bool {
    if !sb.has_metadata_csum() {
        return true;
    }
    let Some(calculated) = inode_checksum(sb, inode_no, inode) else {
        return false;
    };
    let provided_lo = u16::from_le_bytes([
        inode[INODE_CHECKSUM_LO_OFFSET],
        inode[INODE_CHECKSUM_LO_OFFSET + 1],
    ]);
    let has_high = inode.len() >= INODE_CHECKSUM_HI_OFFSET + 2
        && inode.len() >= INODE_EXTRA_ISIZE_OFFSET + 2
        && u16::from_le_bytes([
            inode[INODE_EXTRA_ISIZE_OFFSET],
            inode[INODE_EXTRA_ISIZE_OFFSET + 1],
        ]) >= 4;
    if has_high {
        let provided_hi = u16::from_le_bytes([
            inode[INODE_CHECKSUM_HI_OFFSET],
            inode[INODE_CHECKSUM_HI_OFFSET + 1],
        ]);
        (provided_lo as u32 | ((provided_hi as u32) << 16)) == calculated
    } else {
        provided_lo == calculated as u16
    }
}

/// Calculate the 16-bit group-descriptor checksum. `bg_checksum` is zero
/// while hashing. The caller supplies the descriptor's actual on-disk size
/// (32 bytes on non-64-bit ext4 and usually 64 bytes otherwise).
pub fn group_desc_checksum(sb: &Superblock, group: u32, desc: &[u8]) -> Option<u16> {
    if !sb.has_metadata_csum() || desc.len() < GROUP_DESC_CHECKSUM_OFFSET + 2 {
        return None;
    }
    let mut state = crc32c(seed(sb), &group.to_le_bytes());
    state = crc32c(state, &desc[..GROUP_DESC_CHECKSUM_OFFSET]);
    state = crc32c(state, &[0, 0]);
    state = crc32c(state, &desc[GROUP_DESC_CHECKSUM_OFFSET + 2..]);
    Some(state as u16)
}

/// Update `bg_checksum` in a group descriptor in place.
pub fn write_group_desc_checksum(sb: &Superblock, group: u32, desc: &mut [u8]) -> Option<()> {
    let checksum = group_desc_checksum(sb, group, desc)?;
    desc[GROUP_DESC_CHECKSUM_OFFSET..GROUP_DESC_CHECKSUM_OFFSET + 2]
        .copy_from_slice(&checksum.to_le_bytes());
    Some(())
}

/// Verify the stored group-descriptor checksum.
pub fn verify_group_desc_checksum(sb: &Superblock, group: u32, desc: &[u8]) -> bool {
    if !sb.has_metadata_csum() {
        return true;
    }
    let Some(calculated) = group_desc_checksum(sb, group, desc) else {
        return false;
    };
    let provided = u16::from_le_bytes([
        desc[GROUP_DESC_CHECKSUM_OFFSET],
        desc[GROUP_DESC_CHECKSUM_OFFSET + 1],
    ]);
    provided == calculated
}

/// Calculate a block- or inode-bitmap checksum. The descriptor stores the
/// low 16 bits on every ext4 layout and the high 16 bits when its size is 64
/// bytes or greater. Unlike group descriptors, bitmap checksums do not add
/// the group number: their location is already named by the descriptor that
/// carries the result.
pub fn bitmap_checksum(sb: &Superblock, bitmap: &[u8]) -> Option<u32> {
    if !sb.has_metadata_csum() {
        return None;
    }
    Some(crc32c(seed(sb), bitmap))
}

/// Install a block- or inode-bitmap checksum in its group descriptor.
///
/// `bitmap` must contain exactly the meaningful bitmap bytes
/// (`blocks_per_group / 8` or `inodes_per_group / 8`), not necessarily the
/// whole filesystem block. ext4 stores the low half in every descriptor and
/// the high half in a 64-byte descriptor.
pub fn write_bitmap_checksum(
    sb: &Superblock,
    desc: &mut [u8],
    bitmap: &[u8],
    inode_bitmap: bool,
) -> Option<()> {
    let checksum = bitmap_checksum(sb, bitmap)?;
    let lo_off = if inode_bitmap { 0x1a } else { 0x18 };
    let hi_off = if inode_bitmap { 0x3a } else { 0x38 };
    if desc.len() < lo_off + 2 {
        return None;
    }
    desc[lo_off..lo_off + 2].copy_from_slice(&(checksum as u16).to_le_bytes());
    if desc.len() >= hi_off + 2 {
        desc[hi_off..hi_off + 2].copy_from_slice(&((checksum >> 16) as u16).to_le_bytes());
    }
    Some(())
}

/// Verify a bitmap checksum stored in a group descriptor.
pub fn verify_bitmap_checksum(
    sb: &Superblock,
    desc: &[u8],
    bitmap: &[u8],
    inode_bitmap: bool,
) -> bool {
    if !sb.has_metadata_csum() {
        return true;
    }
    let Some(calculated) = bitmap_checksum(sb, bitmap) else {
        return false;
    };
    let lo_off = if inode_bitmap { 0x1a } else { 0x18 };
    let hi_off = if inode_bitmap { 0x3a } else { 0x38 };
    if desc.len() < lo_off + 2 {
        return false;
    }
    let mut provided = u16::from_le_bytes([desc[lo_off], desc[lo_off + 1]]) as u32;
    if desc.len() >= hi_off + 2 {
        provided |= (u16::from_le_bytes([desc[hi_off], desc[hi_off + 1]]) as u32) << 16;
        provided == calculated
    } else {
        provided == calculated as u16 as u32
    }
}

/// Calculate a classic (non-HTREE) directory block checksum. The trailing
/// 12-byte fake dirent belongs to the checksum carrier and is excluded from
/// the byte range being protected.
pub fn directory_block_checksum(
    sb: &Superblock,
    inode_no: u32,
    inode_generation: u32,
    block: &[u8],
) -> Option<u32> {
    if !sb.has_metadata_csum() || block.len() < 12 {
        return None;
    }
    let mut state = crc32c(seed(sb), &inode_no.to_le_bytes());
    state = crc32c(state, &inode_generation.to_le_bytes());
    Some(crc32c(state, &block[..block.len() - 12]))
}

/// Update the checksum in the trailing fake directory entry. Returns `None`
/// unless the block actually has the ext4 directory-tail shape.
pub fn write_directory_block_checksum(
    sb: &Superblock,
    inode_no: u32,
    inode_generation: u32,
    block: &mut [u8],
) -> Option<()> {
    let tail = block.len().checked_sub(12)?;
    if block[tail..tail + 4] != [0; 4]
        || block[tail + 4..tail + 6] != 12u16.to_le_bytes()
        || block[tail + 6] != 0
        || block[tail + 7] != 0xde
    {
        return None;
    }
    let checksum = directory_block_checksum(sb, inode_no, inode_generation, block)?;
    block[tail + 8..tail + 12].copy_from_slice(&checksum.to_le_bytes());
    Some(())
}

/// Verify the checksum carried by a classic directory leaf tail.
pub fn verify_directory_block_checksum(
    sb: &Superblock,
    inode_no: u32,
    inode_generation: u32,
    block: &[u8],
) -> bool {
    if !sb.has_metadata_csum() {
        return true;
    }
    let Some(tail) = block.len().checked_sub(12) else {
        return false;
    };
    if block[tail..tail + 4] != [0; 4]
        || block[tail + 4..tail + 6] != 12u16.to_le_bytes()
        || block[tail + 6] != 0
        || block[tail + 7] != 0xde
    {
        return false;
    }
    let Some(calculated) = directory_block_checksum(sb, inode_no, inode_generation, block) else {
        return false;
    };
    let provided = u32::from_le_bytes(
        block[tail + 8..tail + 12]
            .try_into()
            .expect("directory checksum slice is four bytes"),
    );
    provided == calculated
}

/// Calculate the checksum for a non-root extent-tree block. The final four
/// bytes carry the checksum and are excluded from the protected extent-node
/// bytes.
pub fn extent_block_checksum(
    sb: &Superblock,
    inode_no: u32,
    inode_generation: u32,
    block: &[u8],
) -> Option<u32> {
    if !sb.has_metadata_csum() || block.len() < 4 {
        return None;
    }
    let mut state = crc32c(seed(sb), &inode_no.to_le_bytes());
    state = crc32c(state, &inode_generation.to_le_bytes());
    Some(crc32c(state, &block[..block.len() - 4]))
}

/// Update the checksum stored in the final four bytes of an extent-tree
/// block. The caller must only use this for an ext4 extent block, never for
/// the 60-byte root stored directly in an inode.
pub fn write_extent_block_checksum(
    sb: &Superblock,
    inode_no: u32,
    inode_generation: u32,
    block: &mut [u8],
) -> Option<()> {
    let checksum = extent_block_checksum(sb, inode_no, inode_generation, block)?;
    let off = block.len().checked_sub(4)?;
    block[off..].copy_from_slice(&checksum.to_le_bytes());
    Some(())
}
