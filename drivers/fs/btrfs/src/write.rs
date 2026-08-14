//! Copy-on-write mutations: file writes (overwrite / partial / append / grow)
//! and namespace operations (`create` / `unlink`) in the default subvolume.
//!
//! All mutations share one closed-form COW mini-transaction ([`commit_txn`]):
//! given the fully-edited fs leaf, it reads the extent/csum/root/free-space
//! trees, frees the old blocks of every copied tree, records the new ones in the
//! extent tree, maintains the free-space tree, repoints the affected `ROOT_ITEM`s,
//! writes every node, and flips the superblock last. **Every** tree may be
//! multi-leaf: each is re-packed into as many real leaves as it needs under an
//! internal root. The extent tree records its own new blocks (a self-reference),
//! so how many leaves it and the free-space tree need depends on the block count
//! they produce — [`commit_txn`] resolves this with a fixed point over the leaf
//! counts, re-handing-out node addresses from the same base each round until they
//! stabilise. This replaces the delayed-ref loop real btrfs uses.
//!
//! Scope: a regular file in the default subvolume with any number of existing
//! extents (each exclusively owned + uncompressed, or a hole/inline). A write
//! reads the current file, applies the new bytes at any offset (growing past EOF
//! as needed), then re-tiles the whole content into fresh data extents of at most
//! 128 KiB, freeing the old ones — a genuine copy-on-write mini-transaction that
//! never mutates live data or metadata in place. Per write it:
//!
//! 1. allocates + writes the new data extents, and their per-sector CRC32C **data
//!    checksums** (updated in the CSUM tree; the old extent's csums removed);
//! 2. rebuilds the fs leaf (`EXTENT_DATA` repointed/resized, `INODE_ITEM`
//!    size/generation updated);
//! 3. rebuilds the **extent tree** leaf: frees the old data extent + old COWed
//!    metadata blocks, records the new data extent (with an `EXTENT_DATA_REF`)
//!    and every new metadata block (skinny `METADATA_ITEM` + `TREE_BLOCK_REF`),
//!    and adjusts the block group's `used`;
//! 4. on a `space_cache=v2` image, rebuilds the **free-space tree** leaf: marks
//!    the new data extent's range used (carved out of its containing free extent)
//!    and returns the old data + old metadata blocks to free space, merging with
//!    adjacent free extents but never across a block-group boundary;
//! 5. rebuilds the root leaf so the `FS_TREE`/`CSUM`/`EXTENT`/`FREE_SPACE`
//!    `ROOT_ITEM`s name the new roots (bytenr + generation);
//! 6. writes a fresh superblock (generation + 1) last, atomically switching.
//!
//! Result: a real Linux kernel mounts the image read-write, reads the written
//! file (data-checksum verified) AND writes to it, and `btrfs check` reports no
//! errors — verified end to end on both a plain image and a `space_cache=v2`
//! (free-space-tree) image.
//!
//! **Every tree may be any height** (fs, extent, csum, root, dev, chunk,
//! free-space): it is read into one logical leaf, edited, then re-packed into as
//! many real leaves as needed and internal nodes stacked over them up to a single
//! root of arbitrary level (`commit_txn` / [`grow_add_chunk`] via
//! [`pack_tree_at`]), so a file / directory / extent / checksum set can outgrow a
//! single leaf — or a single internal node — as it does on a laptop-scale root,
//! and chunk growth works even when those trees have already split (its new
//! chunk-tree blocks stay in the system chunk). On an image with a free-space
//! tree, **space is reclaimed**: the allocator ([`Allocator`]) carves new extents
//! / nodes from the tree's free ranges (skipping system block groups), so blocks
//! freed by earlier transactions are reused instead of leaked. A block group's
//! free space is tracked in whichever form it already uses — `FREE_SPACE_EXTENT`
//! items, or a `FREE_SPACE_BITMAP` once it is fragmented (bits toggled, extent
//! count recomputed). Bound: trees grow to at most `BTRFS_MAX_LEVEL` (8) levels.
//! Every superblock copy is updated in lockstep, so
//! images large enough to carry the 64 MiB / 256 GiB mirrors stay `btrfs
//! check`-clean, and a grown chunk is placed clear of the mirror bands
//! (`chunk_span_avoiding_supers`).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::allocator::Allocator;
use crate::btree::{
    self, internal_blockptr, internal_child_slot, internal_key, leaf_item_data, leaf_item_key,
    leaf_item_span, leaf_lower_bound, level, nritems, HEADER_SIZE,
};
use crate::checksum::{block_csum, name_hash};
use crate::dir::decode_dir_items;
use crate::format::{self, le64, BtrfsKey};
use crate::inode::InodeItem;
use crate::roots;
use crate::volume::BtrfsVolume;

// Header field offsets rewritten when a node is stamped.
const HDR_BYTENR: usize = 48;
const HDR_GENERATION: usize = 80;

/// On-disk size of one leaf item entry (key + offset + size).
const LEAF_ITEM_SIZE: usize = format::DISK_KEY_SIZE + 8;

/// Insert `(key, body)` into leaf `buf` at `slot`. btrfs requires the data area
/// to stay packed in item order (item `k`'s data ends exactly where item `k-1`'s
/// begins), so the data of items at/after `slot` is shifted down to open a
/// correctly-placed hole. `NoSpace` if the leaf is full (no node split).
fn leaf_insert(buf: &mut [u8], slot: usize, key: &BtrfsKey, body: &[u8]) -> Result<(), FsError> {
    let nodesize = buf.len();
    let n = nritems(buf)? as usize;
    let dsize = body.len();
    // Lowest data offset in use (start of free space; data grows down).
    let mut min_off = nodesize - HEADER_SIZE;
    for i in 0..n {
        let (off, _size) = leaf_item_span(buf, i)?;
        min_off = min_off.min(off);
    }
    let items_end = HEADER_SIZE + n * LEAF_ITEM_SIZE;
    let free = (HEADER_SIZE + min_off)
        .checked_sub(items_end)
        .ok_or(FsError::InvalidData)?;
    if free < LEAF_ITEM_SIZE + dsize {
        return Err(FsError::NoSpace);
    }

    // The new data goes directly below item `slot-1`'s data (or at the top for
    // slot 0). Shift the data of items at/after `slot` down by `dsize`.
    let boundary = if slot == 0 {
        nodesize - HEADER_SIZE
    } else {
        leaf_item_span(buf, slot - 1)?.0
    };
    let data_lo = HEADER_SIZE + min_off;
    let data_hi = HEADER_SIZE + boundary;
    buf.copy_within(data_lo..data_hi, data_lo - dsize);
    // Items whose data moved (offset < boundary, i.e. slots >= slot) drop by dsize.
    for i in 0..n {
        let base = HEADER_SIZE + i * LEAF_ITEM_SIZE + format::DISK_KEY_SIZE;
        let o = format::le32(buf, base)? as usize;
        if o < boundary {
            buf[base..base + 4].copy_from_slice(&((o - dsize) as u32).to_le_bytes());
        }
    }

    // Shift item entries [slot..n) right by one to open a hole at `slot`.
    let src = HEADER_SIZE + slot * LEAF_ITEM_SIZE;
    let move_len = (n - slot) * LEAF_ITEM_SIZE;
    buf.copy_within(src..src + move_len, src + LEAF_ITEM_SIZE);

    // Place the new body + item entry.
    let new_off = boundary - dsize;
    buf[HEADER_SIZE + new_off..HEADER_SIZE + new_off + dsize].copy_from_slice(body);
    let ie = HEADER_SIZE + slot * LEAF_ITEM_SIZE;
    buf[ie..ie + 8].copy_from_slice(&key.objectid.to_le_bytes());
    buf[ie + 8] = key.item_type;
    buf[ie + 9..ie + 17].copy_from_slice(&key.offset.to_le_bytes());
    buf[ie + 17..ie + 21].copy_from_slice(&(new_off as u32).to_le_bytes());
    buf[ie + 21..ie + 25].copy_from_slice(&(dsize as u32).to_le_bytes());

    buf[96..100].copy_from_slice(&((n + 1) as u32).to_le_bytes());
    Ok(())
}

/// Find the slot of the item exactly matching `key` in a leaf, or `None`.
fn leaf_find(buf: &[u8], key: &BtrfsKey) -> Result<Option<usize>, FsError> {
    let n = nritems(buf)? as usize;
    let slot = leaf_lower_bound(buf, n, key)?;
    if slot < n && leaf_item_key(buf, slot)? == *key {
        Ok(Some(slot))
    } else {
        Ok(None)
    }
}

/// Delete item `slot` from a leaf: remove its data (compacting the data area and
/// fixing the offsets of items below it) and its item entry.
fn leaf_delete(buf: &mut [u8], slot: usize) -> Result<(), FsError> {
    let nodesize = buf.len();
    let n = nritems(buf)? as usize;
    if slot >= n {
        return Err(FsError::InvalidData);
    }
    let (off, size) = leaf_item_span(buf, slot)?;
    let mut min_off = nodesize - HEADER_SIZE;
    for i in 0..n {
        let (o, _s) = leaf_item_span(buf, i)?;
        min_off = min_off.min(o);
    }
    // Move the data below the hole up by `size`, then bump those items' offsets.
    let data_start = HEADER_SIZE + min_off;
    let hole_start = HEADER_SIZE + off;
    buf.copy_within(data_start..hole_start, data_start + size);
    for i in 0..n {
        if i == slot {
            continue;
        }
        let base = HEADER_SIZE + i * LEAF_ITEM_SIZE + format::DISK_KEY_SIZE;
        let o = format::le32(buf, base)? as usize;
        if o < off {
            buf[base..base + 4].copy_from_slice(&((o + size) as u32).to_le_bytes());
        }
    }
    // Remove the item entry by shifting the following entries left.
    let src = HEADER_SIZE + (slot + 1) * LEAF_ITEM_SIZE;
    let dst = HEADER_SIZE + slot * LEAF_ITEM_SIZE;
    let move_len = (n - 1 - slot) * LEAF_ITEM_SIZE;
    buf.copy_within(src..src + move_len, dst);
    buf[96..100].copy_from_slice(&((n - 1) as u32).to_le_bytes());
    Ok(())
}

/// Insert `(key, body)` into a leaf at its sorted position (the key must be
/// absent). Convenience over [`leaf_insert`] that finds the slot.
fn leaf_insert_sorted(buf: &mut [u8], key: &BtrfsKey, body: &[u8]) -> Result<(), FsError> {
    let n = nritems(buf)? as usize;
    let slot = leaf_lower_bound(buf, n, key)?;
    leaf_insert(buf, slot, key, body)
}

/// Stamp a node buffer with `addr`/`gen`/CRC32C in place (no allocation, no
/// write) — used by the pre-allocated mini-transaction.
pub(crate) fn stamp_node(buf: &mut [u8], addr: u64, gen: u64) {
    buf[HDR_BYTENR..HDR_BYTENR + 8].copy_from_slice(&addr.to_le_bytes());
    buf[HDR_GENERATION..HDR_GENERATION + 8].copy_from_slice(&gen.to_le_bytes());
    let csum = block_csum(&buf[format::CSUM_SIZE..]);
    buf[0..4].copy_from_slice(&csum.to_le_bytes());
    for b in &mut buf[4..format::CSUM_SIZE] {
        *b = 0;
    }
}

// Inline backref types within an extent item.
const TREE_BLOCK_REF_KEY: u8 = 176;
const EXTENT_DATA_REF_KEY: u8 = 178;
const EXTENT_FLAG_DATA: u64 = 1;
const EXTENT_FLAG_TREE_BLOCK: u64 = 2;

/// Skinny `METADATA_ITEM` body for a tree block owned by `owner_root` (33 bytes):
/// `btrfs_extent_item{refs=1,gen,flags=TREE_BLOCK}` + inline `TREE_BLOCK_REF`.
fn ext_item_meta(gen: u64, owner_root: u64) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 33];
    v[0..8].copy_from_slice(&1u64.to_le_bytes());
    v[8..16].copy_from_slice(&gen.to_le_bytes());
    v[16..24].copy_from_slice(&EXTENT_FLAG_TREE_BLOCK.to_le_bytes());
    v[24] = TREE_BLOCK_REF_KEY;
    v[25..33].copy_from_slice(&owner_root.to_le_bytes());
    v
}

/// `EXTENT_ITEM` body for a data extent (53 bytes): `btrfs_extent_item{refs=1,
/// gen,flags=DATA}` + inline `EXTENT_DATA_REF{root, objectid, offset, count=1}`.
/// `offset` is the extent's file position (the `EXTENT_DATA` key offset minus its
/// `extent_offset`) — the value `btrfs check` recomputes for the back-reference.
fn ext_item_data(gen: u64, root: u64, objectid: u64, offset: u64) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 53];
    v[0..8].copy_from_slice(&1u64.to_le_bytes());
    v[8..16].copy_from_slice(&gen.to_le_bytes());
    v[16..24].copy_from_slice(&EXTENT_FLAG_DATA.to_le_bytes());
    v[24] = EXTENT_DATA_REF_KEY;
    v[25..33].copy_from_slice(&root.to_le_bytes()); // ref root
    v[33..41].copy_from_slice(&objectid.to_le_bytes()); // ref objectid (inode)
    v[41..49].copy_from_slice(&offset.to_le_bytes()); // ref offset (file position)
    v[49..53].copy_from_slice(&1u32.to_le_bytes()); // ref count
    v
}

/// First leaf slot whose key matches `(objectid, item_type)` (any offset).
fn leaf_find_by_type(buf: &[u8], objectid: u64, item_type: u8) -> Result<Option<usize>, FsError> {
    let n = nritems(buf)? as usize;
    for i in 0..n {
        let k = leaf_item_key(buf, i)?;
        if k.objectid == objectid && k.item_type == item_type {
            return Ok(Some(i));
        }
    }
    Ok(None)
}

/// Replace item `slot`'s body in place (must be the same size).
fn leaf_replace_inplace(buf: &mut [u8], slot: usize, body: &[u8]) -> Result<(), FsError> {
    let (off, size) = leaf_item_span(buf, slot)?;
    if size != body.len() {
        return Err(FsError::Unsupported);
    }
    let start = HEADER_SIZE + off;
    buf[start..start + size].copy_from_slice(body);
    Ok(())
}

/// Adjust the `used` byte count of the block group covering `addr` by `delta`.
fn block_group_add_used(buf: &mut [u8], addr: u64, delta: i64) -> Result<(), FsError> {
    let n = nritems(buf)? as usize;
    for i in 0..n {
        let k = leaf_item_key(buf, i)?;
        if k.item_type == format::BLOCK_GROUP_ITEM_KEY
            && addr >= k.objectid
            && addr < k.objectid.saturating_add(k.offset)
        {
            let (off, _size) = leaf_item_span(buf, i)?;
            let start = HEADER_SIZE + off;
            let used = format::le64(buf, start)?;
            let new_used = (used as i64 + delta) as u64;
            buf[start..start + 8].copy_from_slice(&new_used.to_le_bytes());
            return Ok(());
        }
    }
    Err(FsError::InvalidData)
}

/// `(block_group_start, length)` of the block group covering `addr`, from the
/// extent leaf's `BLOCK_GROUP_ITEM`s.
fn block_group_of(buf: &[u8], addr: u64) -> Result<Option<(u64, u64)>, FsError> {
    let n = nritems(buf)? as usize;
    for i in 0..n {
        let k = leaf_item_key(buf, i)?;
        if k.item_type == format::BLOCK_GROUP_ITEM_KEY
            && addr >= k.objectid
            && addr < k.objectid.saturating_add(k.offset)
        {
            return Ok(Some((k.objectid, k.offset)));
        }
    }
    Ok(None)
}

// ── Free-space tree (space_cache=v2) ───────────────────────────────
//
// A block group tracks its free space either as `FREE_SPACE_EXTENT` items (one
// per free range) or, once fragmented enough that a bitmap is more compact, as
// `FREE_SPACE_BITMAP` items (one bit per sector, set = free) — selected by the
// `USING_BITMAPS` flag in its `FREE_SPACE_INFO`. We never convert between the
// two; we maintain whichever form a block group already uses.

/// `FREE_SPACE_INFO.flags` bit set when a block group tracks free space with
/// bitmaps (`BTRFS_FREE_SPACE_USING_BITMAPS`).
const FREE_SPACE_USING_BITMAPS: u32 = 1;

/// Adjust an extent-mode block group's `FREE_SPACE_INFO.extent_count` by `delta`.
fn fst_info_adjust(fst_leaf: &mut [u8], bg_start: u64, delta: i64) -> Result<(), FsError> {
    let n = nritems(fst_leaf)? as usize;
    for i in 0..n {
        let k = leaf_item_key(fst_leaf, i)?;
        if k.item_type == format::FREE_SPACE_INFO_KEY && k.objectid == bg_start {
            let (off, _s) = leaf_item_span(fst_leaf, i)?;
            let start = HEADER_SIZE + off;
            let count = format::le32(fst_leaf, start)?;
            let new = (count as i64 + delta) as u32;
            fst_leaf[start..start + 4].copy_from_slice(&new.to_le_bytes());
            return Ok(());
        }
    }
    Err(FsError::InvalidData)
}

/// Whether the block group at `bg_start` tracks free space with bitmaps.
fn fst_bg_uses_bitmaps(fst_leaf: &[u8], bg_start: u64) -> Result<bool, FsError> {
    let n = nritems(fst_leaf)? as usize;
    for i in 0..n {
        let k = leaf_item_key(fst_leaf, i)?;
        if k.item_type == format::FREE_SPACE_INFO_KEY && k.objectid == bg_start {
            let (off, _) = leaf_item_span(fst_leaf, i)?;
            // FREE_SPACE_INFO body: extent_count@0, flags@4.
            let flags = format::le32(fst_leaf, HEADER_SIZE + off + 4)?;
            return Ok(flags & FREE_SPACE_USING_BITMAPS != 0);
        }
    }
    Err(FsError::InvalidData)
}

/// Set (`free`) or clear the bit for every sector of `[start, start+len)` in the
/// block group's bitmap item(s) — a range may span more than one bitmap, each of
/// which covers `sectorsize * 8 * body_len` bytes. Bits are little-endian: bit
/// `i` of a bitmap covering `range_start` is the sector at `range_start + i*ss`.
fn fst_bitmap_set(
    fst_leaf: &mut [u8],
    sectorsize: u64,
    start: u64,
    len: u64,
    free: bool,
) -> Result<(), FsError> {
    let mut addr = start;
    while addr < start + len {
        let n = nritems(fst_leaf)? as usize;
        let mut hit: Option<(usize, u64)> = None;
        for i in 0..n {
            let k = leaf_item_key(fst_leaf, i)?;
            if k.item_type == format::FREE_SPACE_BITMAP_KEY
                && k.objectid <= addr
                && addr < k.objectid.saturating_add(k.offset)
            {
                hit = Some((i, k.objectid));
                break;
            }
        }
        let (slot, range_start) = hit.ok_or(FsError::InvalidData)?;
        let (off, size) = leaf_item_span(fst_leaf, slot)?;
        let bit = ((addr - range_start) / sectorsize) as usize;
        if bit / 8 >= size {
            return Err(FsError::InvalidData);
        }
        let byte = HEADER_SIZE + off + bit / 8;
        let mask = 1u8 << (bit % 8);
        if free {
            fst_leaf[byte] |= mask;
        } else {
            fst_leaf[byte] &= !mask;
        }
        addr += sectorsize;
    }
    Ok(())
}

/// Recompute a bitmap block group's `FREE_SPACE_INFO.extent_count` — the number
/// of maximal runs of free (set) sectors across all its bitmaps, treating
/// contiguous bitmaps as one bitstream (a run continues across a bitmap boundary).
fn fst_bitmap_recount(
    fst_leaf: &mut [u8],
    sectorsize: u64,
    bg_start: u64,
    bg_len: u64,
) -> Result<(), FsError> {
    let bg_end = bg_start + bg_len;
    let mut maps: Vec<(u64, usize, usize)> = Vec::new(); // (range_start, off, nbits)
    let n = nritems(fst_leaf)? as usize;
    for i in 0..n {
        let k = leaf_item_key(fst_leaf, i)?;
        if k.item_type == format::FREE_SPACE_BITMAP_KEY
            && k.objectid >= bg_start
            && k.objectid < bg_end
        {
            let (off, _size) = leaf_item_span(fst_leaf, i)?;
            maps.push((k.objectid, off, (k.offset / sectorsize) as usize));
        }
    }
    maps.sort_unstable_by_key(|m| m.0);
    let mut runs = 0u32;
    let mut prev_free = false;
    let mut prev_end = bg_start;
    for (range_start, off, nbits) in maps {
        if range_start != prev_end {
            prev_free = false; // a gap between bitmaps breaks a run
        }
        for bit in 0..nbits {
            let free = fst_leaf[HEADER_SIZE + off + bit / 8] & (1u8 << (bit % 8)) != 0;
            if free && !prev_free {
                runs += 1;
            }
            prev_free = free;
        }
        prev_end = range_start + nbits as u64 * sectorsize;
    }
    let n = nritems(fst_leaf)? as usize;
    for i in 0..n {
        let k = leaf_item_key(fst_leaf, i)?;
        if k.item_type == format::FREE_SPACE_INFO_KEY && k.objectid == bg_start {
            let (off, _) = leaf_item_span(fst_leaf, i)?;
            fst_leaf[HEADER_SIZE + off..HEADER_SIZE + off + 4].copy_from_slice(&runs.to_le_bytes());
            return Ok(());
        }
    }
    Err(FsError::InvalidData)
}

/// Mark `[start, start+len)` USED in the free-space tree. In a bitmap block group
/// this clears the range's bits; in an extent-mode one it carves the range out of
/// the `FREE_SPACE_EXTENT` that contains it (leaving up to two remainders).
fn fst_mark_used(
    fst_leaf: &mut [u8],
    sectorsize: u64,
    bg_start: u64,
    bg_len: u64,
    start: u64,
    len: u64,
) -> Result<(), FsError> {
    if fst_bg_uses_bitmaps(fst_leaf, bg_start)? {
        fst_bitmap_set(fst_leaf, sectorsize, start, len, false)?;
        return fst_bitmap_recount(fst_leaf, sectorsize, bg_start, bg_len);
    }
    let end = start + len;
    let n = nritems(fst_leaf)? as usize;
    let mut found: Option<(usize, u64, u64)> = None;
    for i in 0..n {
        let k = leaf_item_key(fst_leaf, i)?;
        if k.item_type == format::FREE_SPACE_EXTENT_KEY
            && k.objectid <= start
            && end <= k.objectid.saturating_add(k.offset)
        {
            found = Some((i, k.objectid, k.offset));
            break;
        }
    }
    let (slot, f, fl) = found.ok_or(FsError::InvalidData)?;
    leaf_delete(fst_leaf, slot)?;
    let mut added = 0i64;
    if f < start {
        leaf_insert_sorted(
            fst_leaf,
            &BtrfsKey::new(f, format::FREE_SPACE_EXTENT_KEY, start - f),
            &[],
        )?;
        added += 1;
    }
    if end < f + fl {
        leaf_insert_sorted(
            fst_leaf,
            &BtrfsKey::new(end, format::FREE_SPACE_EXTENT_KEY, (f + fl) - end),
            &[],
        )?;
        added += 1;
    }
    fst_info_adjust(fst_leaf, bg_start, added - 1)
}

/// Mark `[start, start+len)` FREE in the free-space tree: add it back, merging
/// with an immediately adjacent free extent on either side — but only within the
/// same block group `[bg_start, bg_start+bg_len)` (free extents never span a
/// block-group boundary, so a neighbour in an adjacent group must not be merged).
fn fst_mark_free(
    fst_leaf: &mut [u8],
    sectorsize: u64,
    bg_start: u64,
    bg_len: u64,
    start: u64,
    len: u64,
) -> Result<(), FsError> {
    if fst_bg_uses_bitmaps(fst_leaf, bg_start)? {
        fst_bitmap_set(fst_leaf, sectorsize, start, len, true)?;
        return fst_bitmap_recount(fst_leaf, sectorsize, bg_start, bg_len);
    }
    let bg_end = bg_start + bg_len;
    let mut new_start = start;
    let mut new_end = start + len;
    let n = nritems(fst_leaf)? as usize;
    let mut to_delete: Vec<usize> = Vec::new();
    for i in 0..n {
        let k = leaf_item_key(fst_leaf, i)?;
        if k.item_type != format::FREE_SPACE_EXTENT_KEY {
            continue;
        }
        // Only merge with a neighbour inside this block group.
        if k.objectid < bg_start || k.objectid.saturating_add(k.offset) > bg_end {
            continue;
        }
        if k.objectid.saturating_add(k.offset) == start {
            new_start = k.objectid; // left neighbour
            to_delete.push(i);
        } else if k.objectid == start + len {
            new_end = k.objectid + k.offset; // right neighbour
            to_delete.push(i);
        }
    }
    let removed = to_delete.len() as i64;
    to_delete.sort_unstable();
    for slot in to_delete.into_iter().rev() {
        leaf_delete(fst_leaf, slot)?;
    }
    leaf_insert_sorted(
        fst_leaf,
        &BtrfsKey::new(
            new_start,
            format::FREE_SPACE_EXTENT_KEY,
            new_end - new_start,
        ),
        &[],
    )?;
    fst_info_adjust(fst_leaf, bg_start, 1 - removed)
}

/// Round `x` up to a multiple of `align` (a power of two).
fn align_up(x: u64, align: u64) -> u64 {
    (x + (align - 1)) & !(align - 1)
}

/// One stripe reserved around each superblock mirror so a chunk never overlaps it.
const SUPER_MIRROR_BAND: u64 = 65536;

/// A superblock mirror is written straight to its physical device offset, so a
/// data/metadata chunk must never cover one. Given a physical `start` (the
/// device high-water) and the device's `avail_end`, return `(start, max_len)`:
/// `start` bumped past any mirror band it lands in, and `max_len` capped so
/// `[start, start+max_len)` stops before the next mirror band. The mirror then
/// sits in unallocated device space (the primary at 64 KiB precedes any chunk).
pub(crate) fn chunk_span_avoiding_supers(mut start: u64, avail_end: u64) -> (u64, u64) {
    for &m in format::SUPERBLOCK_MIRROR_OFFSETS.iter() {
        if m != format::SUPERBLOCK_OFFSET && start >= m && start < m + SUPER_MIRROR_BAND {
            start = m + SUPER_MIRROR_BAND;
        }
    }
    let mut end = avail_end;
    for &m in format::SUPERBLOCK_MIRROR_OFFSETS.iter() {
        if m != format::SUPERBLOCK_OFFSET && m >= start && m < end {
            end = m;
        }
    }
    (start, end.saturating_sub(start))
}

/// Largest data extent a single write emits; a bigger file is tiled into several.
/// Matches btrfs's preference for bounded, contiguous data extents.
const MAX_WRITE_EXTENT: u64 = 128 * 1024;

/// Write `data` at byte `offset` into file `ino` via COW: read-modify-write the
/// whole file, then re-tile it into fresh data extents (each at most
/// [`MAX_WRITE_EXTENT`]), freeing the old ones. Supports overwrite, partial write,
/// append and grow of a file with **any number** of existing extents.
///
/// The whole file is rewritten each time (so a small write to a large file still
/// costs the file's size); incremental extent splitting is a later optimization.
/// Each existing extent must be exclusively owned and uncompressed (regular or
/// prealloc, `extent_offset == 0`, covering its whole disk extent) or a hole /
/// inline extent — a shared, partial or compressed extent is out of scope
/// (`Unsupported`), since freeing it wholesale would be wrong.
pub async fn cow_write_file<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    inode: &InodeItem,
    offset: u64,
    data: &[u8],
) -> Result<usize, FsError> {
    if !inode.is_regular() {
        return Err(FsError::Unsupported);
    }
    let (fs_root, fs_level) = vol.fs_tree_root();
    if data.is_empty() {
        return Ok(0);
    }

    // ── Classify the existing extents: the disk extents to free, and the old
    //    EXTENT_DATA keys to delete. Reject anything not exclusively owned. ──
    let extents = btree::collect_for(vol, fs_root, ino, format::EXTENT_DATA_KEY).await?;
    let mut freed_data: Vec<(u64, u64)> = Vec::new();
    for (_key, body) in &extents {
        // btrfs_file_extent_item: compression@16, type@20, disk_bytenr@21,
        // disk_num_bytes@29, extent_offset@37, num_bytes@45.
        if body.len() < 21 {
            return Err(FsError::InvalidData);
        }
        if body[20] == format::FILE_EXTENT_INLINE {
            continue; // data lives in the item; no disk extent to free
        }
        if body.len() < 53 {
            return Err(FsError::InvalidData);
        }
        if body[16] != 0 {
            return Err(FsError::Unsupported); // compressed: out of scope
        }
        let disk_bytenr = le64(body, 21)?;
        if disk_bytenr == 0 {
            continue; // a hole: no disk extent
        }
        let disk_num = le64(body, 29)?;
        if le64(body, 37)? != 0 || le64(body, 45)? != disk_num {
            return Err(FsError::Unsupported); // partial / shared reference
        }
        freed_data.push((disk_bytenr, disk_num));
    }
    let old_data_total: u64 = freed_data.iter().map(|&(_, l)| l).sum();

    // ── Read-modify-write the whole file into one buffer ───────────
    let old_size = inode.size;
    let end = offset
        .checked_add(data.len() as u64)
        .ok_or(FsError::InvalidData)?;
    let new_size = old_size.max(end);
    let sectorsize = u64::from(vol.sectorsize());
    let disk_total = align_up(new_size, sectorsize).max(sectorsize);

    let mut buf = alloc::vec![0u8; new_size as usize];
    if old_size > 0 {
        crate::extent::read_file(
            vol,
            fs_root,
            ino,
            old_size,
            0,
            &mut buf[..old_size as usize],
        )
        .await?;
    }
    let o = offset as usize;
    buf[o..o + data.len()].copy_from_slice(data);

    let gen = vol.superblock().generation + 1;
    let mut alloc = Allocator::build(vol).await?;

    // ── Tile the content into fresh extents; write each + its checksums ─
    let mut new_data: Vec<DataRef> = Vec::new();
    let mut new_eds: Vec<(BtrfsKey, Vec<u8>)> = Vec::new();
    let mut file_off = 0u64;
    while file_off < disk_total {
        let ext_len = (disk_total - file_off).min(MAX_WRITE_EXTENT);
        let e_data = alloc.alloc_data(vol, ext_len)?;
        let mut payload = alloc::vec![0u8; ext_len as usize];
        let copy_end = (file_off + ext_len).min(new_size);
        if file_off < new_size {
            let (s, e) = (file_off as usize, copy_end as usize);
            payload[..e - s].copy_from_slice(&buf[s..e]);
        }
        vol.write_logical(e_data, &payload).await?;
        let csums = crate::csum::compute_csums(&payload, sectorsize as usize);
        new_data.push(DataRef {
            bytenr: e_data,
            len: ext_len,
            ref_root: format::FS_TREE_OBJECTID,
            objectid: ino,
            offset: file_off,
            csums,
        });
        new_eds.push((
            BtrfsKey::new(ino, format::EXTENT_DATA_KEY, file_off),
            file_extent_reg(gen, e_data, ext_len),
        ));
        file_off += ext_len;
    }

    // ── Path-COW the fs tree: drop every old EXTENT_DATA, add the new tiling,
    //    and update the inode (found via a lookup, not a full tree read) —
    //    COWing only the touched paths rather than rebuilding the whole tree. ──
    let mut edits: Vec<Edit> = Vec::new();
    for (key, _) in &extents {
        edits.push(Edit::Delete(*key));
    }
    for (key, body) in &new_eds {
        edits.push(Edit::Upsert(*key, body.clone()));
    }
    let inode_key = BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0);
    let mut new_inode = btree::find_item(vol, fs_root, &inode_key)
        .await?
        .ok_or(FsError::NotFound)?;
    new_inode[0..8].copy_from_slice(&gen.to_le_bytes()); // generation
    new_inode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    new_inode[16..24].copy_from_slice(&new_size.to_le_bytes()); // size
    new_inode[24..32].copy_from_slice(&disk_total.to_le_bytes()); // nbytes
    edits.push(Edit::Upsert(inode_key, new_inode));

    let out = PathCow::new(vol, gen, fs_root, fs_level)
        .await?
        .apply(&mut alloc, &edits)
        .await?;
    let fs = fs_commit_from(out, gen);

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: FsChange::Cow(fs),
            freed_data,
            new_data,
            data_used_delta: disk_total as i64 - old_data_total as i64,
        },
    )
    .await?;
    Ok(data.len())
}

/// Stamp a path-COW's new nodes and package them as an [`FsCommit`].
fn fs_commit_from(out: CowOut, gen: u64) -> FsCommit {
    let new_blocks: Vec<(u64, u8)> = out.nodes.iter().map(|&(a, _, l)| (a, l)).collect();
    let mut nodes = Vec::with_capacity(out.nodes.len());
    for (addr, mut buf, _lvl) in out.nodes {
        stamp_node(&mut buf, addr, gen);
        nodes.push((addr, buf));
    }
    FsCommit {
        nodes,
        new_blocks,
        freed: out.freed,
        root: out.root_addr,
        level: out.root_level,
    }
}

// ── Shared COW mini-transaction ────────────────────────────────────

/// On-disk size of one internal `struct btrfs_key_ptr` (key + blockptr + gen).
const KEY_PTR_SIZE: usize = format::DISK_KEY_SIZE + 16;

/// A data extent recorded into the extent tree as an `EXTENT_ITEM` +
/// `EXTENT_DATA_REF{root, objectid, offset, count=1}`, with the per-sector
/// CRC32C `csums` the csum tree records for it. `offset` is the extent's position
/// in the file (its `EXTENT_DATA` key offset).
struct DataRef {
    bytenr: u64,
    len: u64,
    ref_root: u64,
    objectid: u64,
    offset: u64,
    csums: Vec<u8>,
}

/// A path-COWed tree: the new nodes to write (addr, stamped buffer), the new and
/// freed blocks (addr, level) for extent accounting, and the new root.
pub(crate) struct FsCommit {
    pub nodes: Vec<(u64, Vec<u8>)>,
    pub new_blocks: Vec<(u64, u8)>,
    pub freed: Vec<(u64, u8)>,
    pub root: u64,
    pub level: u8,
}

/// `commit_txn`'s built fs tree: `(nodes, new_meta, freed, root, level)`.
type FsBuilt = (
    Vec<(u64, Vec<u8>)>,
    Vec<(u64, u64, u8)>,
    Vec<(u64, u8)>,
    u64,
    u8,
);

/// How a mutation delivers its fs-tree edit to `commit_txn`.
enum FsChange {
    /// The whole edited fs tree as one logical leaf (re-packed on commit), plus
    /// every old fs block it replaces. Used by the namespace mutations.
    Whole {
        content: Vec<u8>,
        old_blocks: Vec<(u64, u8)>,
    },
    /// A pre-built path-COW of only the touched paths (the write path). Its nodes
    /// were already allocated from the same allocator, before `commit_txn` runs.
    Cow(FsCommit),
}

/// One mutation's fs-tree edit plus the data-extent bookkeeping the
/// extent/free-space/csum trees must reflect. `commit_txn` reads the
/// extent/csum/root/free-space trees itself, applies the data + metadata deltas,
/// re-packs each into as many leaves as it needs, allocates every new block,
/// stamps them, and flips the superblock.
struct Txn {
    /// The fs tree's edit (whole-repack, or a pre-built path COW).
    fs: FsChange,
    /// Data extents whose `EXTENT_ITEM` + csums are removed (bytenr, disk length).
    freed_data: Vec<(u64, u64)>,
    /// Data extents whose `EXTENT_ITEM` + csums are added.
    new_data: Vec<DataRef>,
    /// Net change to the block group's data `used` byte count.
    data_used_delta: i64,
}

/// Pack `items` (key-ordered) into a leaf buffer built on `header` (a
/// `HEADER_SIZE`-byte fs-node header template), sized to `capacity` bytes so
/// later `leaf_insert`s have room. Item entries grow from the front, bodies from
/// the back — the on-disk leaf layout.
fn pack_leaf(header: &[u8], items: &[(BtrfsKey, &[u8])], capacity: usize) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; capacity];
    buf[0..HEADER_SIZE].copy_from_slice(&header[0..HEADER_SIZE]);
    buf[100] = 0; // level 0 (leaf)
    buf[96..100].copy_from_slice(&(items.len() as u32).to_le_bytes());
    let mut data_end = capacity - HEADER_SIZE; // data grows down from the end
    for (i, (key, body)) in items.iter().enumerate() {
        let off = data_end - body.len();
        buf[HEADER_SIZE + off..HEADER_SIZE + off + body.len()].copy_from_slice(body);
        let ie = HEADER_SIZE + i * LEAF_ITEM_SIZE;
        buf[ie..ie + 8].copy_from_slice(&key.objectid.to_le_bytes());
        buf[ie + 8] = key.item_type;
        buf[ie + 9..ie + 17].copy_from_slice(&key.offset.to_le_bytes());
        buf[ie + 17..ie + 21].copy_from_slice(&(off as u32).to_le_bytes());
        buf[ie + 21..ie + 25].copy_from_slice(&(body.len() as u32).to_le_bytes());
        data_end = off;
    }
    buf
}

// ── Path copy-on-write node primitives (Stage 1) ───────────────────
//
// These re-tile the contents of ONE node that a path-COW edit touched into as
// many `nodesize` nodes as they need (a node that overflows an edit is split,
// possibly into several). They are pure — addresses and CRC32C stamps are
// assigned by the walk that COWs the path (Stage 2). Re-tiling reuses the same
// greedy grouping the whole-tree builder uses, so a produced node is always a
// valid, bounds-respecting node, for any item sizes.

/// Pack one internal node over `ptrs` (`(first_key, child_addr, child_gen)`) at
/// `level`. Each pointer records its child's own generation — critical for path
/// COW, where an internal node points at both freshly-COWed children (this txn's
/// generation) and shared children carried over unchanged (their old generation);
/// `btrfs check`'s parent-transid verify compares them. Unstamped.
fn pack_internal(
    header: &[u8],
    ptrs: &[(BtrfsKey, u64, u64)],
    nodesize: usize,
    level: u8,
) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; nodesize];
    buf[0..HEADER_SIZE].copy_from_slice(&header[0..HEADER_SIZE]);
    buf[100] = level;
    buf[96..100].copy_from_slice(&(ptrs.len() as u32).to_le_bytes());
    for (i, (key, addr, cgen)) in ptrs.iter().enumerate() {
        let kp = HEADER_SIZE + i * KEY_PTR_SIZE;
        buf[kp..kp + 8].copy_from_slice(&key.objectid.to_le_bytes());
        buf[kp + 8] = key.item_type;
        buf[kp + 9..kp + 17].copy_from_slice(&key.offset.to_le_bytes());
        buf[kp + 17..kp + 25].copy_from_slice(&addr.to_le_bytes());
        buf[kp + 25..kp + 33].copy_from_slice(&cgen.to_le_bytes());
    }
    buf
}

/// The child generation recorded in internal node `buf`'s key-ptr `i`.
fn internal_gen(buf: &[u8], i: usize) -> Result<u64, FsError> {
    format::le64(
        buf,
        HEADER_SIZE + i * KEY_PTR_SIZE + format::DISK_KEY_SIZE + 8,
    )
}

/// Re-tile `items` (key-ordered) into one or more leaves, greedily filling each
/// to `nodesize`. Returns the leaf buffers (unstamped); at least one, even for an
/// empty item set. `Unsupported` if a single item can't fit a node.
fn regroup_leaves(
    header: &[u8],
    items: &[(BtrfsKey, Vec<u8>)],
    nodesize: usize,
) -> Result<Vec<Vec<u8>>, FsError> {
    let cap = nodesize - HEADER_SIZE;
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut used = 0usize;
    for i in 0..items.len() {
        let need = LEAF_ITEM_SIZE + items[i].1.len();
        if need > cap {
            return Err(FsError::Unsupported);
        }
        if used + need > cap && i > start {
            let refs: Vec<(BtrfsKey, &[u8])> = items[start..i]
                .iter()
                .map(|(k, b)| (*k, b.as_slice()))
                .collect();
            out.push(pack_leaf(header, &refs, nodesize));
            start = i;
            used = 0;
        }
        used += need;
    }
    let refs: Vec<(BtrfsKey, &[u8])> = items[start..]
        .iter()
        .map(|(k, b)| (*k, b.as_slice()))
        .collect();
    out.push(pack_leaf(header, &refs, nodesize));
    Ok(out)
}

/// Re-tile `ptrs` (key-ordered `(first_key, child_addr, child_gen)`) into one or
/// more internal nodes at `level`, greedily filling each. Returns the node buffers.
pub(crate) fn regroup_internal(
    header: &[u8],
    ptrs: &[(BtrfsKey, u64, u64)],
    nodesize: usize,
    level: u8,
) -> Vec<Vec<u8>> {
    let fanout = node_fanout(nodesize).max(1);
    ptrs.chunks(fanout)
        .map(|c| pack_internal(header, c, nodesize, level))
        .collect()
}

/// Collect a leaf's `(key, body)` items.
fn leaf_items(leaf: &[u8]) -> Result<Vec<(BtrfsKey, Vec<u8>)>, FsError> {
    let n = nritems(leaf)? as usize;
    (0..n)
        .map(|i| Ok((leaf_item_key(leaf, i)?, leaf_item_data(leaf, i)?.to_vec())))
        .collect()
}

/// Upsert `(key, body)` into `leaf`, returning the re-tiled replacement leaves
/// (one, or several if the edit overflowed the node).
pub(crate) fn cow_leaf_upsert(
    leaf: &[u8],
    key: &BtrfsKey,
    body: &[u8],
    nodesize: usize,
) -> Result<Vec<Vec<u8>>, FsError> {
    let mut items = leaf_items(leaf)?;
    match items.binary_search_by(|(k, _)| k.cmp(key)) {
        Ok(i) => items[i].1 = body.to_vec(),
        Err(i) => items.insert(i, (*key, body.to_vec())),
    }
    regroup_leaves(leaf, &items, nodesize)
}

/// Delete `key` from `leaf` (if present), returning the re-tiled replacement
/// leaves (always at least one, possibly empty).
pub(crate) fn cow_leaf_delete(
    leaf: &[u8],
    key: &BtrfsKey,
    nodesize: usize,
) -> Result<Vec<Vec<u8>>, FsError> {
    let mut items = leaf_items(leaf)?;
    if let Ok(i) = items.binary_search_by(|(k, _)| k.cmp(key)) {
        items.remove(i);
    }
    regroup_leaves(leaf, &items, nodesize)
}

// ── Path copy-on-write engine (Stage 2) ────────────────────────────
//
// Applies a batch of key edits to one b-tree, COWing only the root-to-leaf paths
// they touch and re-tiling any node an edit overflows (or empties). Nodes are
// held in a per-transaction cache: a node COWed earlier in the batch is edited
// again in place rather than re-allocated, and a node allocated then superseded
// within the batch is dropped rather than recorded as freed. Cost is
// O(edits · log N), not O(tree size).

/// One ancestor recorded on a path-COW descent: `(addr, level, key-ptrs, slot)`.
type PathEntry = (u64, u8, Vec<(BtrfsKey, u64, u64)>, usize);

/// One key edit for [`PathCow`].
pub(crate) enum Edit {
    /// Insert `key`, or replace its body if present.
    Upsert(BtrfsKey, Vec<u8>),
    /// Remove `key` if present.
    Delete(BtrfsKey),
}

impl Edit {
    fn key(&self) -> &BtrfsKey {
        match self {
            Edit::Upsert(k, _) | Edit::Delete(k) => k,
        }
    }
}

/// The result of path-COWing a tree: its new root, the new blocks to write
/// (unstamped) with their levels, and the committed blocks it freed.
pub(crate) struct CowOut {
    pub root_addr: u64,
    pub root_level: u8,
    pub nodes: Vec<(u64, Vec<u8>, u8)>, // (addr, buf, level)
    pub freed: Vec<(u64, u8)>,          // (addr, level) — committed blocks only
}

/// Path-COW working state for one tree within one transaction.
pub(crate) struct PathCow<'a, B: BlockDevice + 'static> {
    vol: &'a BtrfsVolume<B>,
    gen: u64,
    nodesize: usize,
    header: Vec<u8>,
    /// New blocks made this txn (addr → (buf, level)); superseded by later edits.
    pending: BTreeMap<u64, (Vec<u8>, u8)>,
    /// Committed (pre-txn) blocks this batch frees.
    freed: Vec<(u64, u8)>,
    root: u64,
    root_level: u8,
}

impl<'a, B: BlockDevice + 'static> PathCow<'a, B> {
    /// Start a path-COW of the tree rooted at `(root, root_level)`. Reads the root
    /// once for a header template.
    pub(crate) async fn new(
        vol: &'a BtrfsVolume<B>,
        gen: u64,
        root: u64,
        root_level: u8,
    ) -> Result<Self, FsError> {
        let header = vol.read_node(root).await?[..HEADER_SIZE].to_vec();
        Ok(PathCow {
            vol,
            gen,
            nodesize: vol.nodesize(),
            header,
            pending: BTreeMap::new(),
            freed: Vec::new(),
            root,
            root_level,
        })
    }

    /// Read a node — from this txn's cache if COWed, else from disk.
    async fn read(&self, addr: u64) -> Result<Vec<u8>, FsError> {
        match self.pending.get(&addr) {
            Some((buf, _)) => Ok(buf.clone()),
            None => self.vol.read_node(addr).await,
        }
    }

    /// Retire the block at `addr`: if it was made this txn, drop it (never
    /// committed); otherwise record it as a freed committed block.
    fn retire(&mut self, addr: u64, level: u8) {
        if self.pending.remove(&addr).is_none() {
            self.freed.push((addr, level));
        }
    }

    /// Allocate + cache a new node, returning its address.
    fn store(&mut self, alloc: &mut Allocator, buf: Vec<u8>, level: u8) -> Result<u64, FsError> {
        let addr = alloc.alloc_node(self.vol)?;
        self.pending.insert(addr, (buf, level));
        Ok(addr)
    }

    /// First key of a leaf/internal node buffer (for the pointer to it).
    fn first_key(buf: &[u8]) -> Result<BtrfsKey, FsError> {
        if nritems(buf)? == 0 {
            return Ok(BtrfsKey::new(0, 0, 0));
        }
        if level(buf)? == 0 {
            leaf_item_key(buf, 0)
        } else {
            internal_key(buf, 0)
        }
    }

    /// Store each re-tiled node and return the `(first_key, addr)` pointers to
    /// them (empty when `bufs` is a single empty leaf — the child is removed).
    fn store_all(
        &mut self,
        alloc: &mut Allocator,
        bufs: Vec<Vec<u8>>,
        level: u8,
    ) -> Result<Vec<(BtrfsKey, u64, u64)>, FsError> {
        if bufs.len() == 1 && nritems(&bufs[0])? == 0 && (self.root_level > 0 || level > 0) {
            return Ok(Vec::new()); // an emptied non-root node: drop it
        }
        let mut ptrs = Vec::with_capacity(bufs.len());
        for buf in bufs {
            let key = Self::first_key(&buf)?;
            let addr = self.store(alloc, buf, level)?;
            // A stored node is fresh this txn, so its pointer records this gen.
            ptrs.push((key, addr, self.gen));
        }
        Ok(ptrs)
    }

    /// Apply one edit, updating the working root.
    async fn apply_one(&mut self, alloc: &mut Allocator, edit: &Edit) -> Result<(), FsError> {
        // Descend to the target leaf, recording each internal node's pointer list
        // and the child slot taken.
        let target = *edit.key();
        // Each ancestor on the descent: (addr, level, its key-ptrs, child slot).
        let mut path: Vec<PathEntry> = Vec::new();
        let mut addr = self.root;
        let leaf = loop {
            let buf = self.read(addr).await?;
            if level(&buf)? == 0 {
                break buf;
            }
            let n = nritems(&buf)? as usize;
            let slot = internal_child_slot(&buf, n, &target)?;
            let ptrs: Vec<(BtrfsKey, u64, u64)> = (0..n)
                .map(|i| {
                    Ok((
                        internal_key(&buf, i)?,
                        internal_blockptr(&buf, i)?,
                        internal_gen(&buf, i)?,
                    ))
                })
                .collect::<Result<_, FsError>>()?;
            let lvl = level(&buf)?;
            let child = ptrs[slot].1;
            path.push((addr, lvl, ptrs, slot));
            addr = child;
        };

        // Edit + re-tile the leaf.
        let leaf_addr = addr;
        let new_leaves = match edit {
            Edit::Upsert(k, body) => cow_leaf_upsert(&leaf, k, body, self.nodesize)?,
            Edit::Delete(k) => cow_leaf_delete(&leaf, k, self.nodesize)?,
        };
        self.retire(leaf_addr, 0);
        let mut cur_ptrs = self.store_all(alloc, new_leaves, 0)?;
        let mut ptr_level = 0u8;

        // Propagate the replacement pointer(s) up the path, re-tiling as needed.
        while let Some((paddr, plevel, mut ptrs, slot)) = path.pop() {
            self.retire(paddr, plevel);
            ptrs.splice(slot..=slot, cur_ptrs.iter().copied());
            if ptrs.is_empty() {
                cur_ptrs = Vec::new();
                continue;
            }
            let bufs = regroup_internal(&self.header, &ptrs, self.nodesize, plevel);
            cur_ptrs = self.store_all(alloc, bufs, plevel)?;
            ptr_level = plevel;
        }

        // Settle the new root: one node stays the root; several need a new root
        // above them (height grows); none means the tree emptied.
        let (mut root, mut root_level) = match cur_ptrs.len() {
            0 => {
                let empty = pack_leaf(&self.header, &[], self.nodesize);
                (self.store(alloc, empty, 0)?, 0)
            }
            1 => (cur_ptrs[0].1, ptr_level),
            _ => {
                if usize::from(ptr_level) + 1 > MAX_TREE_LEVEL {
                    return Err(FsError::NoSpace);
                }
                let buf = pack_internal(&self.header, &cur_ptrs, self.nodesize, ptr_level + 1);
                (self.store(alloc, buf, ptr_level + 1)?, ptr_level + 1)
            }
        };

        // Collapse a degenerate spine (an internal root with a single child).
        while root_level > 0 {
            let buf = self.read(root).await?;
            if nritems(&buf)? != 1 {
                break;
            }
            let child = internal_blockptr(&buf, 0)?;
            self.retire(root, root_level);
            root = child;
            root_level -= 1;
        }

        self.root = root;
        self.root_level = root_level;
        Ok(())
    }

    /// Apply all `edits`, then finalize: returns the new root + the new/freed
    /// blocks. `alloc` allocates every new node (before the metadata fixed point).
    pub(crate) async fn apply(
        mut self,
        alloc: &mut Allocator,
        edits: &[Edit],
    ) -> Result<CowOut, FsError> {
        for edit in edits {
            self.apply_one(alloc, edit).await?;
        }
        let nodes: Vec<(u64, Vec<u8>, u8)> = self
            .pending
            .into_iter()
            .map(|(a, (b, l))| (a, b, l))
            .collect();
        Ok(CowOut {
            root_addr: self.root,
            root_level: self.root_level,
            nodes,
            freed: self.freed,
        })
    }
}

/// Read every item of the fs tree rooted at `fs_root` (any height) into one
/// oversized logical leaf (with headroom for a mutation's inserts) plus the list
/// of every block the tree currently occupies (all freed on rewrite).
async fn read_fs_oversized<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
) -> Result<(Vec<u8>, Vec<(u64, u8)>), FsError> {
    // Collect all leaf items in key order.
    let mut cursor = btree::Cursor::seek(vol, fs_root, &BtrfsKey::new(0, 0, 0)).await?;
    let mut items: Vec<(BtrfsKey, Vec<u8>)> = Vec::new();
    while let Some((k, data)) = cursor.current()? {
        items.push((k, data.to_vec()));
        cursor.advance().await?;
    }
    // Collect every block in the tree (root + internals + leaves) with its level
    // (a skinny METADATA_ITEM key encodes the block's level in its offset).
    let mut old_blocks: Vec<(u64, u8)> = Vec::new();
    let mut stack = alloc::vec![fs_root];
    while let Some(addr) = stack.pop() {
        let node = vol.read_node(addr).await?;
        let lvl = level(&node)?;
        old_blocks.push((addr, lvl));
        if lvl > 0 {
            for i in 0..nritems(&node)? as usize {
                stack.push(btree::internal_blockptr(&node, i)?);
            }
        }
    }
    // Size the logical leaf to the items plus generous headroom for inserts.
    let header = vol.read_node(fs_root).await?;
    let body_total: usize = items.iter().map(|(_, b)| b.len()).sum();
    let capacity = HEADER_SIZE + items.len() * LEAF_ITEM_SIZE + body_total + 64 * 1024;
    let refs: Vec<(BtrfsKey, &[u8])> = items.iter().map(|(k, b)| (*k, b.as_slice())).collect();
    Ok((pack_leaf(&header, &refs, capacity), old_blocks))
}

/// Greedily group a logical leaf's items into runs that each fit one `nodesize`
/// leaf, returned as `[start, end)` index ranges (one per real leaf). An empty
/// tree yields a single empty leaf `[(0, 0)]`. Errors if one item exceeds a node.
fn group_items<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    logical: &[u8],
) -> Result<Vec<(usize, usize)>, FsError> {
    let leaf_cap = vol.nodesize() - HEADER_SIZE;
    let n = nritems(logical)? as usize;
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut start = 0usize;
    let mut used = 0usize;
    for i in 0..n {
        let (_off, size) = leaf_item_span(logical, i)?;
        let need = LEAF_ITEM_SIZE + size;
        if need > leaf_cap {
            return Err(FsError::Unsupported); // a single item bigger than a node
        }
        if used + need > leaf_cap && i > start {
            groups.push((start, i));
            start = i;
            used = 0;
        }
        used += need;
    }
    groups.push((start, n)); // final (possibly empty) leaf
    Ok(groups)
}

/// btrfs caps tree height (`BTRFS_MAX_LEVEL`): leaves are level 0, the root at
/// most level 7.
const MAX_TREE_LEVEL: usize = 7;

/// Child pointers that fit in one internal node.
fn node_fanout(nodesize: usize) -> usize {
    (nodesize - HEADER_SIZE) / KEY_PTR_SIZE
}

/// Node count at each level of a tree with `leaves` leaves, bottom-up:
/// `[leaves, ceil(leaves/f), …, 1]` (a single leaf is `[1]` — a leaf is its own
/// root). The tree is exactly `levels.len()` levels tall.
pub(crate) fn tree_levels(leaves: usize, nodesize: usize) -> Vec<usize> {
    let f = node_fanout(nodesize).max(1);
    let mut levels = alloc::vec![leaves.max(1)];
    while *levels.last().unwrap() > 1 {
        let n = *levels.last().unwrap();
        levels.push(n.div_ceil(f));
    }
    levels
}

/// Total blocks a tree of `leaves` leaves occupies (leaves + every internal node
/// up to the root).
pub(crate) fn tree_block_count(leaves: usize, nodesize: usize) -> usize {
    tree_levels(leaves, nodesize).iter().sum()
}

/// Pack `logical`'s items into real `nodesize` leaves at the pre-assigned `addrs`,
/// then build internal nodes over them level by level up to a single root —
/// producing a tree of **any height**. `addrs` is consumed bottom-up (all leaves,
/// then all level-1 nodes, …, then the root), matching [`tree_levels`] /
/// [`collect_tree_meta`]. Every node's bytenr/generation/CRC32C is stamped.
/// Returns the new nodes `(addr, bytes)`, the root address, and its level. A tree
/// taller than `BTRFS_MAX_LEVEL` is out of scope (`NoSpace`).
#[allow(clippy::type_complexity)]
fn pack_tree_at<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    logical: &[u8],
    groups: &[(usize, usize)],
    addrs: &[u64],
    gen: u64,
) -> Result<(Vec<(u64, Vec<u8>)>, u64, u8), FsError> {
    let nodesize = vol.nodesize();
    let levels = tree_levels(groups.len(), nodesize);
    if levels.len() > MAX_TREE_LEVEL + 1 {
        return Err(FsError::NoSpace);
    }
    if addrs.len() != levels.iter().sum() {
        return Err(FsError::InvalidData);
    }
    let mut nodes = Vec::new();
    let mut ai = 0usize;

    // Level 0: the leaves. Each pointer up carries the leaf's first key.
    let mut child_ptrs: Vec<(BtrfsKey, u64)> = Vec::new();
    for &(s, e) in groups.iter() {
        let addr = addrs[ai];
        ai += 1;
        let refs: Vec<(BtrfsKey, &[u8])> = (s..e)
            .map(|i| Ok((leaf_item_key(logical, i)?, leaf_item_data(logical, i)?)))
            .collect::<Result<_, FsError>>()?;
        let mut leaf = pack_leaf(logical, &refs, nodesize);
        stamp_node(&mut leaf, addr, gen);
        let first = if e > s {
            leaf_item_key(logical, s)?
        } else {
            BtrfsKey::new(0, 0, 0)
        };
        child_ptrs.push((first, addr));
        nodes.push((addr, leaf));
    }

    // Internal levels 1.. : group the level below into `fanout`-wide nodes. Level
    // `k`'s node carries `key_ptr`s (first key + blockptr + generation) to its
    // children, and its header records the level.
    let fanout = node_fanout(nodesize);
    for (k, &count) in levels.iter().enumerate().skip(1) {
        let mut next: Vec<(BtrfsKey, u64)> = Vec::with_capacity(count);
        for chunk in child_ptrs.chunks(fanout) {
            let addr = addrs[ai];
            ai += 1;
            let mut node = alloc::vec![0u8; nodesize];
            node[0..HEADER_SIZE].copy_from_slice(&logical[0..HEADER_SIZE]);
            node[100] = k as u8; // level
            node[96..100].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
            for (i, (key, caddr)) in chunk.iter().enumerate() {
                let kp = HEADER_SIZE + i * KEY_PTR_SIZE;
                node[kp..kp + 8].copy_from_slice(&key.objectid.to_le_bytes());
                node[kp + 8] = key.item_type;
                node[kp + 9..kp + 17].copy_from_slice(&key.offset.to_le_bytes());
                node[kp + 17..kp + 25].copy_from_slice(&caddr.to_le_bytes());
                node[kp + 25..kp + 33].copy_from_slice(&gen.to_le_bytes()); // key-ptr gen
            }
            stamp_node(&mut node, addr, gen);
            next.push((chunk[0].0, addr));
            nodes.push((addr, node));
        }
        child_ptrs = next;
    }

    let root_level = (levels.len() - 1) as u8;
    Ok((nodes, child_ptrs[0].1, root_level))
}

/// Allocate `n` tree nodes, returning their addresses in allocation order.
fn alloc_nodes<B: BlockDevice + 'static>(
    alloc: &mut Allocator,
    vol: &BtrfsVolume<B>,
    n: usize,
) -> Result<Vec<u64>, FsError> {
    (0..n).map(|_| alloc.alloc_node(vol)).collect()
}

/// A tree's new root `(addr, level)` given its packed nodes' addresses (laid out
/// bottom-up) and its leaf count: the root is the last address, at the top level.
fn tree_root_addr(addrs: &[u64], leaves: usize, nodesize: usize) -> (u64, u8) {
    let levels = tree_levels(leaves, nodesize);
    (*addrs.last().unwrap(), (levels.len() - 1) as u8)
}

/// Bump `cursor` by `n` node-sized blocks within `[.., limit)`, returning their
/// addresses (`NoSpace` if the arena is exhausted). Used by chunk growth to hand
/// out blocks from the system chunk and from the new chunk.
fn take_nodes(cursor: &mut u64, limit: u64, n: usize, nodesize: u64) -> Result<Vec<u64>, FsError> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        if cursor.saturating_add(nodesize) > limit {
            return Err(FsError::NoSpace);
        }
        v.push(*cursor);
        *cursor += nodesize;
    }
    Ok(v)
}

/// Append `(addr, owner, level)` for each block of a tree with `leaves` leaves,
/// bottom-up (all leaves at level 0, then each higher level) — matching the
/// `addrs` layout [`pack_tree_at`] consumes and [`tree_levels`] describes.
fn collect_tree_meta(
    addrs: &[u64],
    leaves: usize,
    nodesize: usize,
    owner: u64,
    out: &mut Vec<(u64, u64, u8)>,
) {
    let mut idx = 0usize;
    for (level, &count) in tree_levels(leaves, nodesize).iter().enumerate() {
        for _ in 0..count {
            out.push((addrs[idx], owner, level as u8));
            idx += 1;
        }
    }
}

/// Finalize a mutation: read the extent/csum/root/free-space trees, apply this
/// mutation's data + metadata deltas, re-pack **every** tree (fs included) into as
/// many real leaves as it needs under an internal root, allocate every new block,
/// stamp and write them, then flip the superblock last so the old trees stay
/// intact until the atomic switch. `alloc` arrives with any data extents already
/// reserved and written.
///
/// The extent tree records its own new blocks, so how many leaves it (and the
/// free-space tree) needs depends on how many blocks the transaction allocates —
/// which depends on those leaf counts. `commit_txn` resolves this with a **fixed
/// point**: it re-hands-out every tree-node address from the same base each
/// iteration (`Allocator::restore`), rebuilds the extent/free-space content, and
/// repeats until their leaf counts stabilise; only the converged addresses are
/// written. This replaces the delayed-ref loop real btrfs uses. Fixed set of
/// block groups (no chunk allocation here — the caller grows and retries on
/// `NoSpace`).
async fn commit_txn<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    gen: u64,
    mut alloc: Allocator,
    txn: Txn,
) -> Result<(), FsError> {
    let nodesize = vol.nodesize() as u64;
    let (root_tree, _) = vol.root_tree_root();

    // The csum tree is only COWed when data extents change (a metadata-only op
    // leaves it untouched). The free-space tree is optional (space_cache=v2).
    let touch_csum = !txn.new_data.is_empty() || !txn.freed_data.is_empty();
    let old_ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    let old_csum = match touch_csum {
        true => Some(
            roots::find_root(vol, root_tree, format::CSUM_TREE_OBJECTID)
                .await?
                .0,
        ),
        false => None,
    };
    let old_fst = roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID)
        .await
        .ok()
        .map(|(r, _)| r);

    // Read every COWed tree (besides fs, which arrives edited) as one oversized
    // logical leaf plus its old blocks. The trees may be any height.
    let (mut ext_logical, ext_old) = read_fs_oversized(vol, old_ext).await?;
    let (mut root_logical, root_old) = read_fs_oversized(vol, root_tree).await?;
    let (csum_logical, csum_old) = match old_csum {
        Some(c) => {
            let (l, o) = read_fs_oversized(vol, c).await?;
            (Some(l), o)
        }
        None => (None, Vec::new()),
    };
    let (fst_base, fst_old) = match old_fst {
        Some(f) => {
            let (l, o) = read_fs_oversized(vol, f).await?;
            (Some(l), o)
        }
        None => (None, Vec::new()),
    };

    // ── csum tree: drop freed extents' csums, add new extents' csums ───
    let csum_logical = match csum_logical {
        Some(mut cl) => {
            for &(bytenr, _) in &txn.freed_data {
                let k = BtrfsKey::new(
                    format::EXTENT_CSUM_OBJECTID,
                    format::EXTENT_CSUM_KEY,
                    bytenr,
                );
                if let Some(s) = leaf_find(&cl, &k)? {
                    leaf_delete(&mut cl, s)?;
                }
            }
            for d in &txn.new_data {
                let k = BtrfsKey::new(
                    format::EXTENT_CSUM_OBJECTID,
                    format::EXTENT_CSUM_KEY,
                    d.bytenr,
                );
                leaf_insert_sorted(&mut cl, &k, &d.csums)?;
            }
            Some(cl)
        }
        None => None,
    };

    // ── extent tree: apply the data deltas (independent of block count) ─
    for &(bytenr, len) in &txn.freed_data {
        if let Some(slot) = leaf_find(
            &ext_logical,
            &BtrfsKey::new(bytenr, format::EXTENT_ITEM_KEY, len),
        )? {
            leaf_delete(&mut ext_logical, slot)?;
        }
    }
    for d in &txn.new_data {
        leaf_insert_sorted(
            &mut ext_logical,
            &BtrfsKey::new(d.bytenr, format::EXTENT_ITEM_KEY, d.len),
            &ext_item_data(gen, d.ref_root, d.objectid, d.offset),
        )?;
    }

    // ── free-space tree: apply the data deltas (block groups live in ext) ─
    let fst_base = match fst_base {
        Some(mut fl) => {
            for d in &txn.new_data {
                let (s, l) = block_group_of(&ext_logical, d.bytenr)?.ok_or(FsError::InvalidData)?;
                fst_mark_used(&mut fl, vol.sectorsize() as u64, s, l, d.bytenr, d.len)?;
            }
            for &(bytenr, len) in &txn.freed_data {
                let (s, l) = block_group_of(&ext_logical, bytenr)?.ok_or(FsError::InvalidData)?;
                fst_mark_free(&mut fl, vol.sectorsize() as u64, s, l, bytenr, len)?;
            }
            Some(fl)
        }
        None => None,
    };

    let ns = vol.nodesize();

    // ── Build the fs tree first (before the metadata fixed point), so its new
    //    blocks are fixed constants the extent/free-space trees record. A
    //    namespace op re-packs its whole edited leaf; the write path arrives with
    //    only the touched paths already path-COWed. Either way the fs nodes are
    //    allocated up front — `base` is the allocator cursor just past them. ──
    let (fs_nodes, fs_new_meta, fs_freed, fs_root_addr, fs_level): FsBuilt = match &txn.fs {
        FsChange::Cow(c) => {
            let new_meta = c
                .new_blocks
                .iter()
                .map(|&(a, l)| (a, format::FS_TREE_OBJECTID, l))
                .collect();
            (c.nodes.clone(), new_meta, c.freed.clone(), c.root, c.level)
        }
        FsChange::Whole {
            content,
            old_blocks,
        } => {
            let groups = group_items(vol, content)?;
            let addrs = alloc_nodes(&mut alloc, vol, tree_block_count(groups.len(), ns))?;
            let mut new_meta = Vec::new();
            collect_tree_meta(
                &addrs,
                groups.len(),
                ns,
                format::FS_TREE_OBJECTID,
                &mut new_meta,
            );
            let (root, level) = tree_root_addr(&addrs, groups.len(), ns);
            let nodes = pack_tree_at(vol, content, &groups, &addrs, gen)?.0;
            (nodes, new_meta, old_blocks.clone(), root, level)
        }
    };

    // Fixed groupings: csum content and the root tree's size are settled.
    let csum_groups = csum_logical
        .as_ref()
        .map(|c| group_items(vol, c))
        .transpose()?;
    let root_groups = group_items(vol, &root_logical)?;

    // Every old block across every COWed tree is returned to free space.
    let mut freed_meta: Vec<(u64, u8)> = fs_freed;
    freed_meta.extend(ext_old);
    freed_meta.extend(root_old);
    freed_meta.extend(csum_old);
    freed_meta.extend(fst_old);

    // ── Metadata fixed point over the extent/free-space leaf counts ────
    let base = alloc.snapshot();
    let csum_nc = csum_groups
        .as_ref()
        .map_or(0, |g| tree_block_count(g.len(), ns));
    let root_nc = tree_block_count(root_groups.len(), ns);
    let mut ext_leaves = 1usize;
    let mut fst_leaves = usize::from(fst_base.is_some());

    struct Converged {
        csum_addrs: Vec<u64>,
        root_addrs: Vec<u64>,
        ext_addrs: Vec<u64>,
        fst_addrs: Vec<u64>,
        new_meta: Vec<(u64, u64, u8)>,
        ext_final: Vec<u8>,
        ext_groups: Vec<(usize, usize)>,
        fst_final: Option<Vec<u8>>,
        fst_groups: Option<Vec<(usize, usize)>>,
    }
    let mut converged: Option<Converged> = None;

    for _ in 0..8 {
        alloc.restore(&base);
        let csum_addrs = alloc_nodes(&mut alloc, vol, csum_nc)?;
        let root_addrs = alloc_nodes(&mut alloc, vol, root_nc)?;
        let ext_addrs = alloc_nodes(&mut alloc, vol, tree_block_count(ext_leaves, ns))?;
        let fst_addrs = alloc_nodes(
            &mut alloc,
            vol,
            if fst_leaves > 0 {
                tree_block_count(fst_leaves, ns)
            } else {
                0
            },
        )?;

        // Every new metadata block. The fs blocks are fixed constants (built
        // above); the rest were just handed out in allocation order.
        let mut new_meta: Vec<(u64, u64, u8)> = fs_new_meta.clone();
        if let Some(g) = &csum_groups {
            collect_tree_meta(
                &csum_addrs,
                g.len(),
                ns,
                format::CSUM_TREE_OBJECTID,
                &mut new_meta,
            );
        }
        collect_tree_meta(
            &root_addrs,
            root_groups.len(),
            ns,
            format::ROOT_TREE_OBJECTID,
            &mut new_meta,
        );
        collect_tree_meta(
            &ext_addrs,
            ext_leaves,
            ns,
            format::EXTENT_TREE_OBJECTID,
            &mut new_meta,
        );
        if fst_leaves > 0 {
            collect_tree_meta(
                &fst_addrs,
                fst_leaves,
                ns,
                format::FREE_SPACE_TREE_OBJECTID,
                &mut new_meta,
            );
        }

        // Extent tree with this iteration's metadata items.
        let mut ext_final = ext_logical.clone();
        for &(blk, lvl) in &freed_meta {
            if let Some(s) = leaf_find(
                &ext_final,
                &BtrfsKey::new(blk, format::METADATA_ITEM_KEY, u64::from(lvl)),
            )? {
                leaf_delete(&mut ext_final, s)?;
            }
        }
        for &(addr, owner, lvl) in &new_meta {
            leaf_insert_sorted(
                &mut ext_final,
                &BtrfsKey::new(addr, format::METADATA_ITEM_KEY, u64::from(lvl)),
                &ext_item_meta(gen, owner),
            )?;
        }
        let ext_groups = group_items(vol, &ext_final)?;

        // Free-space tree with this iteration's used/freed blocks.
        let (fst_final, fst_groups) = match &fst_base {
            Some(fb) => {
                let mut ff = fb.clone();
                for &(addr, _, _) in &new_meta {
                    let (s, l) = block_group_of(&ext_final, addr)?.ok_or(FsError::InvalidData)?;
                    fst_mark_used(&mut ff, vol.sectorsize() as u64, s, l, addr, nodesize)?;
                }
                for &(blk, _) in &freed_meta {
                    let (s, l) = block_group_of(&ext_final, blk)?.ok_or(FsError::InvalidData)?;
                    fst_mark_free(&mut ff, vol.sectorsize() as u64, s, l, blk, nodesize)?;
                }
                let g = group_items(vol, &ff)?;
                (Some(ff), Some(g))
            }
            None => (None, None),
        };

        let ext_lv = ext_groups.len();
        let fst_lv = fst_groups.as_ref().map_or(0, |g| g.len());
        if ext_lv == ext_leaves && fst_lv == fst_leaves {
            converged = Some(Converged {
                csum_addrs,
                root_addrs,
                ext_addrs,
                fst_addrs,
                new_meta,
                ext_final,
                ext_groups,
                fst_final,
                fst_groups,
            });
            break;
        }
        ext_leaves = ext_lv;
        fst_leaves = fst_lv;
    }
    let Converged {
        csum_addrs,
        root_addrs,
        ext_addrs,
        fst_addrs,
        new_meta,
        mut ext_final,
        ext_groups,
        fst_final,
        fst_groups,
    } = converged.ok_or(FsError::NoSpace)?;

    // ── Block-group `used`: charge each block/extent to its own group ──
    // (Values only — this doesn't change any tree's item count or leaf layout.)
    for &(addr, _, _) in &new_meta {
        block_group_add_used(&mut ext_final, addr, nodesize as i64)?;
    }
    for &(blk, _) in &freed_meta {
        block_group_add_used(&mut ext_final, blk, -(nodesize as i64))?;
    }
    for d in &txn.new_data {
        block_group_add_used(&mut ext_final, d.bytenr, d.len as i64)?;
    }
    for &(bytenr, len) in &txn.freed_data {
        block_group_add_used(&mut ext_final, bytenr, -(len as i64))?;
    }

    // ── Root tree: repoint each COWed tree's ROOT_ITEM to its new root ──
    // ROOT_ITEM fields: generation@160, bytenr@176, level@238, generation_v2@239.
    let tree_root =
        |addrs: &[u64], groups: &[(usize, usize)]| tree_root_addr(addrs, groups.len(), ns);
    let (ext_root_addr, ext_level) = tree_root(&ext_addrs, &ext_groups);
    let (root_root_addr, _root_level) = tree_root(&root_addrs, &root_groups);
    let stamp_root_item = |ri: &mut [u8], bytenr: u64, tree_level: u8| {
        ri[160..168].copy_from_slice(&gen.to_le_bytes());
        ri[176..184].copy_from_slice(&bytenr.to_le_bytes());
        ri[238] = tree_level;
        if ri.len() >= 247 {
            ri[239..247].copy_from_slice(&gen.to_le_bytes());
        }
    };
    let mut root_updates = alloc::vec![(format::FS_TREE_OBJECTID, fs_root_addr, fs_level)];
    root_updates.push((format::EXTENT_TREE_OBJECTID, ext_root_addr, ext_level));
    if let (Some(g), Some(c)) = (&csum_groups, csum_logical.as_ref()) {
        let (a, l) = tree_root(&csum_addrs, g);
        let _ = c;
        root_updates.push((format::CSUM_TREE_OBJECTID, a, l));
    }
    if let (Some(g), Some(_)) = (&fst_groups, fst_final.as_ref()) {
        let (a, l) = tree_root(&fst_addrs, g);
        root_updates.push((format::FREE_SPACE_TREE_OBJECTID, a, l));
    }
    for &(owner, new, lvl) in &root_updates {
        let slot = leaf_find_by_type(&root_logical, owner, format::ROOT_ITEM_KEY)?
            .ok_or(FsError::NotFound)?;
        let mut ri = leaf_item_data(&root_logical, slot)?.to_vec();
        stamp_root_item(&mut ri, new, lvl);
        leaf_replace_inplace(&mut root_logical, slot, &ri)?;
    }

    // ── Pack every tree into its real leaves (stamped), then write them ─
    let mut nodes: Vec<(u64, Vec<u8>)> = Vec::new();
    nodes.extend(fs_nodes);
    if let (Some(c), Some(g)) = (&csum_logical, &csum_groups) {
        nodes.extend(pack_tree_at(vol, c, g, &csum_addrs, gen)?.0);
    }
    nodes.extend(pack_tree_at(vol, &ext_final, &ext_groups, &ext_addrs, gen)?.0);
    nodes.extend(pack_tree_at(vol, &root_logical, &root_groups, &root_addrs, gen)?.0);
    if let (Some(f), Some(g)) = (&fst_final, &fst_groups) {
        nodes.extend(pack_tree_at(vol, f, g, &fst_addrs, gen)?.0);
    }
    for (addr, buf) in &nodes {
        vol.write_logical(*addr, buf).await?;
    }

    // Superblock `bytes_used` moves by the net data + metadata change.
    let meta_used_delta = (new_meta.len() as i64 - freed_meta.len() as i64) * nodesize as i64;
    let total_used_delta = txn.data_used_delta + meta_used_delta;

    let mut raw = vol.read_raw_superblock().await?;
    raw[72..80].copy_from_slice(&gen.to_le_bytes()); // generation
    raw[80..88].copy_from_slice(&root_root_addr.to_le_bytes()); // root
                                                                // Keep the superblock's `bytes_used@120` in step with the block groups' `used`.
    let bytes_used = (le64(&raw, 120)? as i64 + total_used_delta) as u64;
    raw[120..128].copy_from_slice(&bytes_used.to_le_bytes());
    let csum = block_csum(&raw[format::CSUM_SIZE..format::SUPERBLOCK_SIZE]);
    raw[0..4].copy_from_slice(&csum.to_le_bytes());
    for b in &mut raw[4..format::CSUM_SIZE] {
        *b = 0;
    }
    vol.flush().await; // data + metadata durable before the superblock flip
    vol.write_superblock(&raw).await?;

    if let Some(f) = alloc.floor() {
        vol.set_alloc_floor(f);
    }
    vol.commit_roots(root_root_addr, fs_root_addr, gen);
    Ok(())
}

// ── Namespace mutations (create / unlink) ──────────────────────────

/// Build a fresh 160-byte `btrfs_inode_item`.
#[allow(clippy::too_many_arguments)]
fn inode_item(
    gen: u64,
    mode: u32,
    size: u64,
    nbytes: u64,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    time_sec: i64,
    time_nsec: u32,
) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 160];
    v[0..8].copy_from_slice(&gen.to_le_bytes()); // generation
    v[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    v[16..24].copy_from_slice(&size.to_le_bytes()); // size
    v[24..32].copy_from_slice(&nbytes.to_le_bytes()); // nbytes
    v[40..44].copy_from_slice(&nlink.to_le_bytes());
    v[44..48].copy_from_slice(&uid.to_le_bytes());
    v[48..52].copy_from_slice(&gid.to_le_bytes());
    v[52..56].copy_from_slice(&mode.to_le_bytes());
    v[56..64].copy_from_slice(&rdev.to_le_bytes());
    // atime@112, ctime@124, mtime@136, otime@148 — a `btrfs_timespec` is
    // {__le64 sec; __le32 nsec} (12 bytes).
    for off in [112usize, 124, 136, 148] {
        v[off..off + 8].copy_from_slice(&(time_sec as u64).to_le_bytes());
        v[off + 8..off + 12].copy_from_slice(&time_nsec.to_le_bytes());
    }
    v
}

/// Build a `btrfs_inode_ref` body: `{__le64 index; __le16 name_len; name}`.
fn inode_ref(index: u64, name: &[u8]) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 10 + name.len()];
    v[0..8].copy_from_slice(&index.to_le_bytes());
    v[8..10].copy_from_slice(&(name.len() as u16).to_le_bytes());
    v[10..].copy_from_slice(name);
    v
}

/// Build a `btrfs_dir_item` body naming inode `child_ino` of `BTRFS_FT_*` type
/// `ft`: `{disk_key location; __le64 transid; __le16 data_len=0; __le16 name_len;
/// u8 type; name}`.
fn dir_item_body(child_ino: u64, gen: u64, ft: u8, name: &[u8]) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 30 + name.len()];
    v[0..8].copy_from_slice(&child_ino.to_le_bytes()); // location.objectid
    v[8] = format::INODE_ITEM_KEY; // location.type
                                   // location.offset@9 = 0
    v[17..25].copy_from_slice(&gen.to_le_bytes()); // transid
                                                   // data_len@25 = 0
    v[27..29].copy_from_slice(&(name.len() as u16).to_le_bytes()); // name_len
    v[29] = ft; // type
    v[30..].copy_from_slice(name);
    v
}

/// Build a 53-byte regular `btrfs_file_extent_item` pointing at a data extent of
/// `len` bytes at logical `disk_bytenr` (uncompressed, extent_offset 0).
fn file_extent_reg(gen: u64, disk_bytenr: u64, len: u64) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 53];
    v[0..8].copy_from_slice(&gen.to_le_bytes()); // generation
    v[8..16].copy_from_slice(&len.to_le_bytes()); // ram_bytes
                                                  // compression@16 / encryption@17 / other_encoding@18 = 0
    v[20] = format::FILE_EXTENT_REG; // type
    v[21..29].copy_from_slice(&disk_bytenr.to_le_bytes()); // disk_bytenr
    v[29..37].copy_from_slice(&len.to_le_bytes()); // disk_num_bytes
                                                   // extent_offset@37 = 0
    v[45..53].copy_from_slice(&len.to_le_bytes()); // num_bytes
    v
}

/// Next free inode number: one past the highest in-range `INODE_ITEM` objectid.
fn next_inode_number(fs_leaf: &[u8]) -> Result<u64, FsError> {
    let n = nritems(fs_leaf)? as usize;
    let mut max = format::FIRST_FREE_OBJECTID;
    for i in 0..n {
        let k = leaf_item_key(fs_leaf, i)?;
        if k.item_type == format::INODE_ITEM_KEY
            && k.objectid >= format::FIRST_FREE_OBJECTID
            && k.objectid <= format::LAST_FREE_OBJECTID
        {
            max = max.max(k.objectid);
        }
    }
    Ok(max + 1)
}

/// Next `DIR_INDEX` sequence for directory `dir_ino`: one past the highest
/// existing index (indices 0/1 are reserved for `.`/`..`, so the first real
/// entry is 2).
fn next_dir_index(fs_leaf: &[u8], dir_ino: u64) -> Result<u64, FsError> {
    let n = nritems(fs_leaf)? as usize;
    let mut max = 1u64;
    for i in 0..n {
        let k = leaf_item_key(fs_leaf, i)?;
        if k.item_type == format::DIR_INDEX_KEY && k.objectid == dir_ino {
            max = max.max(k.offset);
        }
    }
    Ok(max + 1)
}

/// What kind of inode [`create_node`] materialises: mode + directory-entry type,
/// an optional device number (`mknod`), and optional inline content (a symlink
/// target, stored as one inline `EXTENT_DATA`).
struct NewNode<'a> {
    mode: u32,
    ftype: u8,
    rdev: u64,
    inline: Option<&'a [u8]>,
}

/// Create an empty regular file `name` in directory `parent_ino` (default
/// subvolume). Returns the new inode number and its freshly-built [`InodeItem`].
pub async fn create_file<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    name: &str,
) -> Result<(u64, InodeItem), FsError> {
    create_node(
        vol,
        parent_ino,
        name,
        NewNode {
            mode: 0o100644,
            ftype: format::FT_REG_FILE,
            rdev: 0,
            inline: None,
        },
    )
    .await
}

/// Create an empty subdirectory `name` in directory `parent_ino` (default
/// subvolume). Returns the new inode number and its [`InodeItem`]. btrfs
/// directories carry `nlink == 1` (subdirectories are not counted), so the
/// parent's link count is unchanged — only its `i_size` grows.
pub async fn mkdir_dir<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    name: &str,
) -> Result<(u64, InodeItem), FsError> {
    create_node(
        vol,
        parent_ino,
        name,
        NewNode {
            mode: 0o040755,
            ftype: format::FT_DIR,
            rdev: 0,
            inline: None,
        },
    )
    .await
}

/// Create a symlink `name` → `target` in directory `parent_ino` (default
/// subvolume). The target is stored as one uncompressed inline `EXTENT_DATA`,
/// exactly like `btrfs_symlink` (inode `size`/`nbytes`/`ram_bytes` all the target
/// length). Targets `>= sectorsize` are out of scope (`Unsupported`).
pub async fn symlink_node<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    name: &str,
    target: &str,
) -> Result<(u64, InodeItem), FsError> {
    if target.is_empty() || target.len() >= vol.sectorsize() as usize {
        return Err(FsError::Unsupported);
    }
    create_node(
        vol,
        parent_ino,
        name,
        NewNode {
            mode: 0o120777, // S_IFLNK | 0777
            ftype: format::FT_SYMLINK,
            rdev: 0,
            inline: Some(target.as_bytes()),
        },
    )
    .await
}

/// Create a special file `name` (char/block device, FIFO or socket) in directory
/// `parent_ino` (default subvolume). `mode` carries the `S_IF*` type bits; `rdev`
/// is the Linux `dev_t` (0 for FIFO/socket).
pub async fn mknod_node<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    name: &str,
    mode: u32,
    ftype: u8,
    rdev: u64,
) -> Result<(u64, InodeItem), FsError> {
    create_node(
        vol,
        parent_ino,
        name,
        NewNode {
            mode,
            ftype,
            rdev,
            inline: None,
        },
    )
    .await
}

/// Create a new inode named `name` in directory `parent_ino` (default subvolume)
/// via a COW mini-transaction. Single-leaf trees only (like all mutations here).
async fn create_node<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    name: &str,
    spec: NewNode<'_>,
) -> Result<(u64, InodeItem), FsError> {
    let name_bytes = name.as_bytes();
    if name.is_empty() || name_bytes.len() > 255 || name.contains('/') {
        return Err(FsError::InvalidData);
    }

    let (fs_root, _fs_level) = vol.fs_tree_root();
    let (mut fs_leaf, fs_old_blocks) = read_fs_oversized(vol, fs_root).await?;

    // The name's `DIR_ITEM` key must be free: an existing key means either the
    // name already exists (the VFS pre-checks, so this is defensive) or a hash
    // collision, which would need appending to the shared item body (out of
    // scope — a fresh insert at a duplicate key would corrupt leaf order).
    let dir_item_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );
    if leaf_find(&fs_leaf, &dir_item_key)?.is_some() {
        return Err(FsError::Unsupported);
    }

    let new_ino = next_inode_number(&fs_leaf)?;
    let new_index = next_dir_index(&fs_leaf, parent_ino)?;
    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    // Update the parent dir inode: btrfs directory `i_size` is the sum of entry
    // name lengths, so grow it by this name; bump transid + sequence. Borrow the
    // parent's mtime for the new inode's timestamps (no wall clock here).
    let pslot = leaf_find(
        &fs_leaf,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )?
    .ok_or(FsError::NotFound)?;
    let mut pinode = leaf_item_data(&fs_leaf, pslot)?.to_vec();
    let psize = le64(&pinode, 16)?;
    let ptime_sec = le64(&pinode, 136)? as i64;
    let ptime_nsec = format::le32(&pinode, 144)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
                                                       // btrfs directory `i_size` counts each entry's name twice (DIR_ITEM +
                                                       // DIR_INDEX) — see `btrfs_add_link` (`i_size + name->len * 2`).
    pinode[16..24].copy_from_slice(&(psize + 2 * name_bytes.len() as u64).to_le_bytes());
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes()); // sequence
    leaf_replace_inplace(&mut fs_leaf, pslot, &pinode)?;

    // Insert the new inode's items: INODE_ITEM, INODE_REF (→ parent), and the
    // parent's DIR_ITEM (name lookup) + DIR_INDEX (readdir order). Inline content
    // (a symlink target) sets the inode size/nbytes and adds an EXTENT_DATA.
    // An inline symlink's data lives in the item, so `nbytes` equals `size`;
    // empty files/dirs/device nodes own no bytes.
    let size = spec.inline.map(|d| d.len() as u64).unwrap_or(0);
    let ii = inode_item(
        gen, spec.mode, size, size, 1, 0, 0, spec.rdev, ptime_sec, ptime_nsec,
    );
    leaf_insert_sorted(
        &mut fs_leaf,
        &BtrfsKey::new(new_ino, format::INODE_ITEM_KEY, 0),
        &ii,
    )?;
    let iref = inode_ref(new_index, name_bytes);
    leaf_insert_sorted(
        &mut fs_leaf,
        &BtrfsKey::new(new_ino, format::INODE_REF_KEY, parent_ino),
        &iref,
    )?;
    let di = dir_item_body(new_ino, gen, spec.ftype, name_bytes);
    leaf_insert_sorted(&mut fs_leaf, &dir_item_key, &di)?;
    leaf_insert_sorted(
        &mut fs_leaf,
        &BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, new_index),
        &di,
    )?;
    if let Some(data) = spec.inline {
        leaf_insert_sorted(
            &mut fs_leaf,
            &BtrfsKey::new(new_ino, format::EXTENT_DATA_KEY, 0),
            &file_extent_inline(gen, data),
        )?;
    }

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: FsChange::Whole {
                content: fs_leaf,
                old_blocks: fs_old_blocks,
            },
            freed_data: Vec::new(),
            new_data: Vec::new(),
            data_used_delta: 0,
        },
    )
    .await?;

    let inode = InodeItem {
        size,
        mode: spec.mode,
        uid: 0,
        gid: 0,
        nlink: 1,
        rdev: spec.rdev,
        mtime_sec: ptime_sec,
        mtime_nsec: ptime_nsec,
    };
    Ok((new_ino, inode))
}

/// Build an inline `btrfs_file_extent_item` (type INLINE) holding `data`: a
/// 21-byte header (`generation`, `ram_bytes = data.len()`, compression/encryption
/// /other_encoding 0, type) followed by the raw bytes. Used for symlink targets.
fn file_extent_inline(gen: u64, data: &[u8]) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 21 + data.len()];
    v[0..8].copy_from_slice(&gen.to_le_bytes()); // generation
    v[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes()); // ram_bytes
                                                                  // compression@16 / encryption@17 / other_encoding@18 = 0
    v[20] = format::FILE_EXTENT_INLINE; // type
    v[21..].copy_from_slice(data);
    v
}

/// Parse a `btrfs_inode_ref` item body (a run of `{__le64 index; __le16
/// name_len; name}`), returning the `index` of the entry naming `name` and
/// whether the item holds exactly one ref (multiple refs would need in-body
/// editing on delete, which is out of scope).
fn inode_ref_index(body: &[u8], name: &[u8]) -> Result<(u64, bool), FsError> {
    let mut pos = 0usize;
    let mut count = 0usize;
    let mut found: Option<u64> = None;
    while pos < body.len() {
        if body.len() - pos < 10 {
            return Err(FsError::InvalidData);
        }
        let index = le64(body, pos)?;
        let nl = format::le16(body, pos + 8)? as usize;
        let ns = pos + 10;
        let ne = ns.checked_add(nl).ok_or(FsError::InvalidData)?;
        let nm = body.get(ns..ne).ok_or(FsError::InvalidData)?;
        if nm == name {
            found = Some(index);
        }
        count += 1;
        pos = ne;
    }
    Ok((found.ok_or(FsError::NotFound)?, count == 1))
}

/// Remove the entry naming `name` from a `btrfs_inode_ref` item body, returning
/// its `index` (the `DIR_INDEX` offset) and the remaining entries concatenated
/// (empty when it was the only entry — the item should then be deleted).
fn inode_ref_remove(body: &[u8], name: &[u8]) -> Result<(u64, Vec<u8>), FsError> {
    let mut pos = 0usize;
    let mut found: Option<u64> = None;
    let mut remaining = Vec::new();
    while pos < body.len() {
        if body.len() - pos < 10 {
            return Err(FsError::InvalidData);
        }
        let index = le64(body, pos)?;
        let nl = format::le16(body, pos + 8)? as usize;
        let ns = pos + 10;
        let ne = ns.checked_add(nl).ok_or(FsError::InvalidData)?;
        let nm = body.get(ns..ne).ok_or(FsError::InvalidData)?;
        if nm == name && found.is_none() {
            found = Some(index);
        } else {
            remaining.extend_from_slice(&body[pos..ne]);
        }
        pos = ne;
    }
    Ok((found.ok_or(FsError::NotFound)?, remaining))
}

/// Remove the entry `name` from directory `parent_ino` (default subvolume) via a
/// COW mini-transaction. On the inode's **last** link the inode is freed (its
/// `INODE_ITEM` + `EXTENT_DATA` removed, its regular data extents + checksums
/// released); a still-linked inode keeps its data and just loses this name and one
/// `INODE_REF` entry, its `nlink` decremented.
///
/// Scope (else `Unsupported`): a regular file reached by a non-colliding
/// `DIR_ITEM`. Directories (use `rmdir`), subvolume mounts, and hash collisions
/// are rejected.
pub async fn unlink_file<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    name: &str,
) -> Result<(), FsError> {
    let name_bytes = name.as_bytes();
    if name.is_empty() || name.contains('/') {
        return Err(FsError::InvalidData);
    }

    let (fs_root, _) = vol.fs_tree_root();
    let (mut fs_leaf, fs_old_blocks) = read_fs_oversized(vol, fs_root).await?;

    // Resolve the name to a single, non-colliding directory entry.
    let dir_item_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );
    let di_slot = leaf_find(&fs_leaf, &dir_item_key)?.ok_or(FsError::NotFound)?;
    let di_entries = decode_dir_items(leaf_item_data(&fs_leaf, di_slot)?)?;
    if di_entries.len() != 1 {
        return Err(FsError::Unsupported); // hash collision: shared item body
    }
    let entry = &di_entries[0];
    if entry.name != name {
        return Err(FsError::NotFound);
    }
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported); // subvolume mount point
    }
    if entry.ftype == format::FT_DIR {
        return Err(FsError::InvalidData); // a directory: use rmdir
    }
    let child_ino = entry.location.objectid;

    // Load the child inode; directories use rmdir.
    let ci_slot = leaf_find(
        &fs_leaf,
        &BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
    )?
    .ok_or(FsError::NotFound)?;
    let cinode = InodeItem::decode(leaf_item_data(&fs_leaf, ci_slot)?)?;
    if cinode.is_dir() {
        return Err(FsError::InvalidData);
    }
    let last_link = cinode.nlink <= 1;

    // Locate this name's INODE_REF entry: its DIR_INDEX offset + the entries that
    // survive removing it (empty when it was the inode's only ref in this dir).
    let ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, parent_ino);
    let ref_slot = leaf_find(&fs_leaf, &ref_key)?.ok_or(FsError::NotFound)?;
    let (dir_index, ref_remaining) =
        inode_ref_remove(leaf_item_data(&fs_leaf, ref_slot)?, name_bytes)?;

    // On the last link, gather the inode's regular data extents (to free) and its
    // EXTENT_DATA keys (to delete). A still-linked inode keeps its data; inline
    // extents and holes own no separate disk block.
    let mut freed_data: Vec<(u64, u64)> = Vec::new();
    let mut ed_offsets: Vec<u64> = Vec::new();
    if last_link {
        let n = nritems(&fs_leaf)? as usize;
        for i in 0..n {
            let k = leaf_item_key(&fs_leaf, i)?;
            if k.objectid != child_ino || k.item_type != format::EXTENT_DATA_KEY {
                continue;
            }
            ed_offsets.push(k.offset);
            let body = leaf_item_data(&fs_leaf, i)?;
            // type@20; disk_bytenr@21; disk_num_bytes@29.
            if body.len() >= 37 && body[20] != format::FILE_EXTENT_INLINE {
                let disk_bytenr = le64(body, 21)?;
                let disk_num = le64(body, 29)?;
                if disk_bytenr != 0 {
                    freed_data.push((disk_bytenr, disk_num));
                }
            }
        }
    }
    let freed_bytes: u64 = freed_data.iter().map(|&(_, l)| l).sum();

    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    // A surviving inode keeps its INODE_ITEM with `nlink` decremented (in place).
    if !last_link {
        let mut ci = leaf_item_data(&fs_leaf, ci_slot)?.to_vec();
        ci[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
        ci[40..44].copy_from_slice(&(cinode.nlink - 1).to_le_bytes());
        leaf_replace_inplace(&mut fs_leaf, ci_slot, &ci)?;
    }

    // Shrink the parent dir inode by this entry's name length; bump transid+seq.
    let pslot = leaf_find(
        &fs_leaf,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )?
    .ok_or(FsError::NotFound)?;
    let mut pinode = leaf_item_data(&fs_leaf, pslot)?.to_vec();
    let psize = le64(&pinode, 16)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
                                                       // Mirror `btrfs_add_link`'s `name->len * 2` (DIR_ITEM + DIR_INDEX).
    pinode[16..24].copy_from_slice(
        &psize
            .saturating_sub(2 * name_bytes.len() as u64)
            .to_le_bytes(),
    );
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes());
    leaf_replace_inplace(&mut fs_leaf, pslot, &pinode)?;

    // Delete this name's DIR_ITEM + DIR_INDEX; on the last link also the
    // INODE_ITEM + EXTENT_DATA. Drop the whole INODE_REF item only when no entry
    // for this parent survives. Re-find each key (a delete shifts later slots).
    let mut to_delete = alloc::vec![
        dir_item_key,
        BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, dir_index),
    ];
    if ref_remaining.is_empty() {
        to_delete.push(ref_key);
    }
    if last_link {
        to_delete.push(BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0));
        for off in ed_offsets {
            to_delete.push(BtrfsKey::new(child_ino, format::EXTENT_DATA_KEY, off));
        }
    }
    for key in &to_delete {
        let slot = leaf_find(&fs_leaf, key)?.ok_or(FsError::NotFound)?;
        leaf_delete(&mut fs_leaf, slot)?;
    }
    // A surviving inode with other links here keeps a shrunken INODE_REF item.
    if !ref_remaining.is_empty() {
        let slot = leaf_find(&fs_leaf, &ref_key)?.ok_or(FsError::NotFound)?;
        leaf_delete(&mut fs_leaf, slot)?;
        leaf_insert_sorted(&mut fs_leaf, &ref_key, &ref_remaining)?;
    }

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: FsChange::Whole {
                content: fs_leaf,
                old_blocks: fs_old_blocks,
            },
            freed_data,
            new_data: Vec::new(),
            data_used_delta: -(freed_bytes as i64),
        },
    )
    .await?;
    Ok(())
}

/// Remove the empty subdirectory `name` from directory `parent_ino` (default
/// subvolume) via a COW mini-transaction.
///
/// Scope (else the noted error): the child must be a directory (`InvalidData`
/// otherwise — use `unlink`), reached by a single `INODE_REF` and a
/// non-colliding `DIR_ITEM`, and **empty** — any `DIR_ITEM`/`DIR_INDEX` child
/// makes it `Busy`, any other item (e.g. an xattr) makes it `Unsupported`.
/// btrfs directories carry `nlink == 1`, so the parent's link count is unchanged
/// (only its `i_size` shrinks).
pub async fn rmdir_dir<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    name: &str,
) -> Result<(), FsError> {
    let name_bytes = name.as_bytes();
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(FsError::InvalidData);
    }

    let (fs_root, _) = vol.fs_tree_root();
    let (mut fs_leaf, fs_old_blocks) = read_fs_oversized(vol, fs_root).await?;

    // Resolve the name to a single, non-colliding directory entry.
    let dir_item_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );
    let di_slot = leaf_find(&fs_leaf, &dir_item_key)?.ok_or(FsError::NotFound)?;
    let di_entries = decode_dir_items(leaf_item_data(&fs_leaf, di_slot)?)?;
    if di_entries.len() != 1 {
        return Err(FsError::Unsupported);
    }
    let entry = &di_entries[0];
    if entry.name != name {
        return Err(FsError::NotFound);
    }
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported); // subvolume mount point
    }
    if entry.ftype != format::FT_DIR {
        return Err(FsError::InvalidData); // not a directory: use unlink
    }
    let child_ino = entry.location.objectid;

    let ci_slot = leaf_find(
        &fs_leaf,
        &BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
    )?
    .ok_or(FsError::NotFound)?;
    if !InodeItem::decode(leaf_item_data(&fs_leaf, ci_slot)?)?.is_dir() {
        return Err(FsError::InvalidData);
    }

    // The directory must be empty: it may own only its INODE_ITEM and the single
    // INODE_REF back to the parent. A DIR_ITEM/DIR_INDEX child means non-empty
    // (`Busy`); anything else (an xattr) is out of scope (`Unsupported`).
    let n = nritems(&fs_leaf)? as usize;
    for i in 0..n {
        let k = leaf_item_key(&fs_leaf, i)?;
        if k.objectid != child_ino {
            continue;
        }
        match k.item_type {
            format::INODE_ITEM_KEY | format::INODE_REF_KEY => {}
            format::DIR_ITEM_KEY | format::DIR_INDEX_KEY => return Err(FsError::Busy),
            _ => return Err(FsError::Unsupported),
        }
    }

    // The child's INODE_REF back to this dir gives the DIR_INDEX offset.
    let ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, parent_ino);
    let ref_slot = leaf_find(&fs_leaf, &ref_key)?.ok_or(FsError::NotFound)?;
    let (dir_index, single_ref) = inode_ref_index(leaf_item_data(&fs_leaf, ref_slot)?, name_bytes)?;
    if !single_ref {
        return Err(FsError::Unsupported);
    }

    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    // Shrink the parent dir inode by this entry's name (counted twice); bump
    // transid + sequence. The parent's nlink is unchanged (btrfs dirs, nlink 1).
    let pslot = leaf_find(
        &fs_leaf,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )?
    .ok_or(FsError::NotFound)?;
    let mut pinode = leaf_item_data(&fs_leaf, pslot)?.to_vec();
    let psize = le64(&pinode, 16)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    pinode[16..24].copy_from_slice(
        &psize
            .saturating_sub(2 * name_bytes.len() as u64)
            .to_le_bytes(),
    );
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes());
    leaf_replace_inplace(&mut fs_leaf, pslot, &pinode)?;

    // Delete the child's INODE_ITEM + INODE_REF and the parent's DIR_ITEM +
    // DIR_INDEX. Re-find each key because a delete shifts later slots.
    let to_delete = [
        BtrfsKey::new(
            parent_ino,
            format::DIR_ITEM_KEY,
            u64::from(name_hash(name_bytes)),
        ),
        BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, dir_index),
        BtrfsKey::new(child_ino, format::INODE_REF_KEY, parent_ino),
        BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
    ];
    for key in &to_delete {
        let slot = leaf_find(&fs_leaf, key)?.ok_or(FsError::NotFound)?;
        leaf_delete(&mut fs_leaf, slot)?;
    }

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: FsChange::Whole {
                content: fs_leaf,
                old_blocks: fs_old_blocks,
            },
            freed_data: Vec::new(),
            new_data: Vec::new(),
            data_used_delta: 0,
        },
    )
    .await?;
    Ok(())
}

/// Rename entry `old_name` to `new_name` within directory `parent_ino` (default
/// subvolume) via a COW mini-transaction. Works for a file or a directory — the
/// source inode, its data and its link count are untouched; only its directory
/// entries and back-ref are re-keyed. If `new_name` already exists, it is
/// atomically replaced (its inode removed and, for a file, its data extents +
/// checksums freed) — the `QSaveFile`/`rename`-onto-target pattern.
///
/// Scope (else the noted error): same directory only; source and destination
/// reached by a single `INODE_REF` and a non-colliding `DIR_ITEM`. Overwrite
/// requires the same kind (dir↔dir / file↔file, else `InvalidData`), an unshared
/// target (`nlink == 1`), and — for a directory target — that it is empty
/// (`Busy`) and free of xattrs (`Unsupported`).
pub async fn rename_same_dir<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    old_name: &str,
    new_name: &str,
) -> Result<(), FsError> {
    let old_bytes = old_name.as_bytes();
    let new_bytes = new_name.as_bytes();
    for n in [old_name, new_name] {
        if n.is_empty() || n.len() > 255 || n.contains('/') || n == "." || n == ".." {
            return Err(FsError::InvalidData);
        }
    }
    if old_name == new_name {
        return Ok(());
    }

    let (fs_root, _) = vol.fs_tree_root();
    let (mut fs_leaf, fs_old_blocks) = read_fs_oversized(vol, fs_root).await?;

    // Resolve the source to a single, non-colliding entry.
    let old_di_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(old_bytes)),
    );
    let old_di_slot = leaf_find(&fs_leaf, &old_di_key)?.ok_or(FsError::NotFound)?;
    let old_entries = decode_dir_items(leaf_item_data(&fs_leaf, old_di_slot)?)?;
    if old_entries.len() != 1 {
        return Err(FsError::Unsupported); // hash collision on the source
    }
    let entry = &old_entries[0];
    if entry.name != old_name {
        return Err(FsError::NotFound);
    }
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported); // subvolume mount point
    }
    let child_ino = entry.location.objectid;
    let ftype = entry.ftype;
    let source_is_dir = ftype == format::FT_DIR;

    // Resolve the destination. If it already exists, gather what removing it
    // entails (an empty directory, or a file whose data + checksums we free).
    let new_di_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(new_bytes)),
    );
    let mut target: Option<(u64, u64, Vec<u64>)> = None; // (ino, dir_index, ed_offsets)
    let mut freed_data: Vec<(u64, u64)> = Vec::new();
    if let Some(t_slot) = leaf_find(&fs_leaf, &new_di_key)? {
        let t_entries = decode_dir_items(leaf_item_data(&fs_leaf, t_slot)?)?;
        if t_entries.len() != 1 {
            return Err(FsError::Unsupported); // hash collision at the destination
        }
        let t = &t_entries[0];
        if t.name != new_name {
            return Err(FsError::Unsupported);
        }
        if t.location.item_type != format::INODE_ITEM_KEY {
            return Err(FsError::Unsupported); // subvolume mount point
        }
        let t_ino = t.location.objectid;
        let target_is_dir = t.ftype == format::FT_DIR;
        if source_is_dir != target_is_dir {
            return Err(FsError::InvalidData); // EISDIR / ENOTDIR
        }
        let t_islot = leaf_find(&fs_leaf, &BtrfsKey::new(t_ino, format::INODE_ITEM_KEY, 0))?
            .ok_or(FsError::NotFound)?;
        if InodeItem::decode(leaf_item_data(&fs_leaf, t_islot)?)?.nlink != 1 {
            return Err(FsError::Unsupported); // hardlinked target
        }
        let mut ed_offsets = Vec::new();
        let n = nritems(&fs_leaf)? as usize;
        for i in 0..n {
            let k = leaf_item_key(&fs_leaf, i)?;
            if k.objectid != t_ino {
                continue;
            }
            match k.item_type {
                format::INODE_ITEM_KEY | format::INODE_REF_KEY => {}
                format::DIR_ITEM_KEY | format::DIR_INDEX_KEY => {
                    // A directory target must be empty.
                    return Err(FsError::Busy);
                }
                format::EXTENT_DATA_KEY if !target_is_dir => {
                    ed_offsets.push(k.offset);
                    let body = leaf_item_data(&fs_leaf, i)?;
                    if body.len() >= 37 && body[20] != format::FILE_EXTENT_INLINE {
                        let db = le64(body, 21)?;
                        let dn = le64(body, 29)?;
                        if db != 0 {
                            freed_data.push((db, dn));
                        }
                    }
                }
                _ => return Err(FsError::Unsupported), // xattrs etc.
            }
        }
        let t_ref = BtrfsKey::new(t_ino, format::INODE_REF_KEY, parent_ino);
        let t_ref_slot = leaf_find(&fs_leaf, &t_ref)?.ok_or(FsError::NotFound)?;
        let (t_index, t_single) =
            inode_ref_index(leaf_item_data(&fs_leaf, t_ref_slot)?, new_bytes)?;
        if !t_single {
            return Err(FsError::Unsupported);
        }
        target = Some((t_ino, t_index, ed_offsets));
    }
    let overwrite = target.is_some();
    let freed_bytes: u64 = freed_data.iter().map(|&(_, l)| l).sum();

    // The source's INODE_REF back to this dir gives its current DIR_INDEX offset.
    let ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, parent_ino);
    let ref_slot = leaf_find(&fs_leaf, &ref_key)?.ok_or(FsError::NotFound)?;
    let (old_index, single_ref) = inode_ref_index(leaf_item_data(&fs_leaf, ref_slot)?, old_bytes)?;
    if !single_ref {
        return Err(FsError::Unsupported);
    }
    let new_index = next_dir_index(&fs_leaf, parent_ino)?;

    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    // Adjust the parent dir `i_size` (each name counts twice: DIR_ITEM +
    // DIR_INDEX); bump transid + sequence. A plain rename swaps old→new name; an
    // overwrite additionally drops the target's (equal-length) `new` name, so the
    // net change is just the loss of the source's `old` name.
    let pslot = leaf_find(
        &fs_leaf,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )?
    .ok_or(FsError::NotFound)?;
    let mut pinode = leaf_item_data(&fs_leaf, pslot)?.to_vec();
    let psize = le64(&pinode, 16)? as i64;
    let size_delta = if overwrite {
        -2 * old_bytes.len() as i64
    } else {
        2 * (new_bytes.len() as i64 - old_bytes.len() as i64)
    };
    pinode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    pinode[16..24].copy_from_slice(&(psize + size_delta).max(0).to_le_bytes());
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes());
    leaf_replace_inplace(&mut fs_leaf, pslot, &pinode)?;

    // Remove the source's old DIR_ITEM + DIR_INDEX + INODE_REF.
    let mut deletes = alloc::vec![
        old_di_key,
        BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, old_index),
        ref_key,
    ];
    // Remove the overwritten target's DIR_ITEM (at new_di_key) + DIR_INDEX +
    // INODE_REF + INODE_ITEM + any EXTENT_DATA — before re-keying the source into
    // its now-vacated DIR_ITEM slot.
    if let Some((t_ino, t_index, ed_offsets)) = &target {
        deletes.push(new_di_key);
        deletes.push(BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, *t_index));
        deletes.push(BtrfsKey::new(*t_ino, format::INODE_REF_KEY, parent_ino));
        deletes.push(BtrfsKey::new(*t_ino, format::INODE_ITEM_KEY, 0));
        for off in ed_offsets {
            deletes.push(BtrfsKey::new(*t_ino, format::EXTENT_DATA_KEY, *off));
        }
    }
    for key in &deletes {
        let slot = leaf_find(&fs_leaf, key)?.ok_or(FsError::NotFound)?;
        leaf_delete(&mut fs_leaf, slot)?;
    }

    // Insert the new name's DIR_ITEM + DIR_INDEX (fresh index) + INODE_REF.
    let di = dir_item_body(child_ino, gen, ftype, new_bytes);
    leaf_insert_sorted(&mut fs_leaf, &new_di_key, &di)?;
    leaf_insert_sorted(
        &mut fs_leaf,
        &BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, new_index),
        &di,
    )?;
    let iref = inode_ref(new_index, new_bytes);
    leaf_insert_sorted(&mut fs_leaf, &ref_key, &iref)?;

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: FsChange::Whole {
                content: fs_leaf,
                old_blocks: fs_old_blocks,
            },
            freed_data,
            new_data: Vec::new(),
            data_used_delta: -(freed_bytes as i64),
        },
    )
    .await?;
    Ok(())
}

/// Whether `ancestor` is `node` itself or one of its ancestors, walking up the
/// `INODE_REF` chain (each `INODE_REF` key's offset is the parent inode) to the
/// root directory. Bounded against a corrupted cyclic chain. Used to refuse
/// moving a directory into its own subtree.
fn is_ancestor_or_self(fs_leaf: &[u8], ancestor: u64, start: u64) -> Result<bool, FsError> {
    let mut node = start;
    for _ in 0..64 {
        if node == ancestor {
            return Ok(true);
        }
        if node == format::FIRST_FREE_OBJECTID {
            return Ok(false); // reached the subvolume root
        }
        let n = nritems(fs_leaf)? as usize;
        let mut parent = None;
        for i in 0..n {
            let k = leaf_item_key(fs_leaf, i)?;
            if k.objectid == node && k.item_type == format::INODE_REF_KEY {
                parent = Some(k.offset);
                break;
            }
        }
        match parent {
            Some(p) => node = p,
            None => return Ok(false),
        }
    }
    Ok(false)
}

/// Move entry `old_name` from directory `old_parent` to `new_name` in a
/// *different* directory `new_parent` (both in the default subvolume) via one COW
/// mini-transaction. Re-keys the moved inode's `INODE_REF` from the old parent to
/// the new, moves its directory entries, and adjusts both parents' `i_size`. If
/// `new_name` already exists it is atomically replaced (same rules as the
/// same-directory overwrite). Both parents and the moved inode share the single
/// fs leaf.
///
/// Scope (else the noted error): `new_parent != old_parent`; a directory may not
/// move into its own subtree (`InvalidData`); source/target reached by a single
/// `INODE_REF` and a non-colliding `DIR_ITEM`; an overwrite target must match kind
/// (`InvalidData`), be unshared (`nlink == 1`), and — for a directory — be empty
/// (`Busy`) and xattr-free (`Unsupported`).
pub async fn rename_cross_dir<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    old_parent: u64,
    new_parent: u64,
    old_name: &str,
    new_name: &str,
) -> Result<(), FsError> {
    let old_bytes = old_name.as_bytes();
    let new_bytes = new_name.as_bytes();
    for n in [old_name, new_name] {
        if n.is_empty() || n.len() > 255 || n.contains('/') || n == "." || n == ".." {
            return Err(FsError::InvalidData);
        }
    }
    if old_parent == new_parent {
        return Err(FsError::InvalidData); // caller routes same-dir to rename_same_dir
    }

    let (fs_root, _) = vol.fs_tree_root();
    let (mut fs_leaf, fs_old_blocks) = read_fs_oversized(vol, fs_root).await?;

    // Resolve the source in the old parent.
    let old_di_key = BtrfsKey::new(
        old_parent,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(old_bytes)),
    );
    let old_di_slot = leaf_find(&fs_leaf, &old_di_key)?.ok_or(FsError::NotFound)?;
    let old_entries = decode_dir_items(leaf_item_data(&fs_leaf, old_di_slot)?)?;
    if old_entries.len() != 1 {
        return Err(FsError::Unsupported);
    }
    let entry = &old_entries[0];
    if entry.name != old_name {
        return Err(FsError::NotFound);
    }
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported);
    }
    let child_ino = entry.location.objectid;
    let ftype = entry.ftype;
    let source_is_dir = ftype == format::FT_DIR;

    // A directory must not move into itself or a descendant (would orphan a loop).
    if source_is_dir && is_ancestor_or_self(&fs_leaf, child_ino, new_parent)? {
        return Err(FsError::InvalidData);
    }

    // The source's INODE_REF back to the old parent gives its current index.
    let old_ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, old_parent);
    let old_ref_slot = leaf_find(&fs_leaf, &old_ref_key)?.ok_or(FsError::NotFound)?;
    let (old_index, single_ref) =
        inode_ref_index(leaf_item_data(&fs_leaf, old_ref_slot)?, old_bytes)?;
    if !single_ref {
        return Err(FsError::Unsupported);
    }

    // Resolve the destination in the new parent (may exist -> overwrite).
    let new_di_key = BtrfsKey::new(
        new_parent,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(new_bytes)),
    );
    let mut target: Option<(u64, u64, Vec<u64>)> = None; // (ino, dir_index, ed_offsets)
    let mut freed_data: Vec<(u64, u64)> = Vec::new();
    if let Some(t_slot) = leaf_find(&fs_leaf, &new_di_key)? {
        let t_entries = decode_dir_items(leaf_item_data(&fs_leaf, t_slot)?)?;
        if t_entries.len() != 1 {
            return Err(FsError::Unsupported);
        }
        let t = &t_entries[0];
        if t.name != new_name {
            return Err(FsError::Unsupported);
        }
        if t.location.item_type != format::INODE_ITEM_KEY {
            return Err(FsError::Unsupported);
        }
        let t_ino = t.location.objectid;
        let target_is_dir = t.ftype == format::FT_DIR;
        if source_is_dir != target_is_dir {
            return Err(FsError::InvalidData);
        }
        let t_islot = leaf_find(&fs_leaf, &BtrfsKey::new(t_ino, format::INODE_ITEM_KEY, 0))?
            .ok_or(FsError::NotFound)?;
        if InodeItem::decode(leaf_item_data(&fs_leaf, t_islot)?)?.nlink != 1 {
            return Err(FsError::Unsupported);
        }
        let mut ed_offsets = Vec::new();
        let n = nritems(&fs_leaf)? as usize;
        for i in 0..n {
            let k = leaf_item_key(&fs_leaf, i)?;
            if k.objectid != t_ino {
                continue;
            }
            match k.item_type {
                format::INODE_ITEM_KEY | format::INODE_REF_KEY => {}
                format::DIR_ITEM_KEY | format::DIR_INDEX_KEY => return Err(FsError::Busy),
                format::EXTENT_DATA_KEY if !target_is_dir => {
                    ed_offsets.push(k.offset);
                    let body = leaf_item_data(&fs_leaf, i)?;
                    if body.len() >= 37 && body[20] != format::FILE_EXTENT_INLINE {
                        let db = le64(body, 21)?;
                        let dn = le64(body, 29)?;
                        if db != 0 {
                            freed_data.push((db, dn));
                        }
                    }
                }
                _ => return Err(FsError::Unsupported),
            }
        }
        let t_ref = BtrfsKey::new(t_ino, format::INODE_REF_KEY, new_parent);
        let t_ref_slot = leaf_find(&fs_leaf, &t_ref)?.ok_or(FsError::NotFound)?;
        let (t_index, t_single) =
            inode_ref_index(leaf_item_data(&fs_leaf, t_ref_slot)?, new_bytes)?;
        if !t_single {
            return Err(FsError::Unsupported);
        }
        target = Some((t_ino, t_index, ed_offsets));
    }
    let overwrite = target.is_some();
    let freed_bytes: u64 = freed_data.iter().map(|&(_, l)| l).sum();
    let new_index = next_dir_index(&fs_leaf, new_parent)?;

    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    // Update both parents' `i_size` in place (same-size replace, no slot shift):
    // the old parent loses the source name; the new parent gains it (net zero on
    // an overwrite, whose equal-length target name is reused). Bump transid+seq.
    let adjust_dir_size = |fs_leaf: &mut [u8], dir: u64, delta: i64| -> Result<(), FsError> {
        let slot = leaf_find(fs_leaf, &BtrfsKey::new(dir, format::INODE_ITEM_KEY, 0))?
            .ok_or(FsError::NotFound)?;
        let mut ino = leaf_item_data(fs_leaf, slot)?.to_vec();
        let sz = le64(&ino, 16)? as i64;
        ino[8..16].copy_from_slice(&gen.to_le_bytes());
        ino[16..24].copy_from_slice(&(sz + delta).max(0).to_le_bytes());
        let seq = le64(&ino, 72)?;
        ino[72..80].copy_from_slice(&(seq + 1).to_le_bytes());
        leaf_replace_inplace(fs_leaf, slot, &ino)
    };
    adjust_dir_size(&mut fs_leaf, old_parent, -2 * old_bytes.len() as i64)?;
    let new_parent_delta = if overwrite {
        0
    } else {
        2 * new_bytes.len() as i64
    };
    adjust_dir_size(&mut fs_leaf, new_parent, new_parent_delta)?;

    // Remove the source's entries in the old parent + its old INODE_REF, plus the
    // overwritten target's items in the new parent.
    let mut deletes = alloc::vec![
        old_di_key,
        BtrfsKey::new(old_parent, format::DIR_INDEX_KEY, old_index),
        old_ref_key,
    ];
    if let Some((t_ino, t_index, ed_offsets)) = &target {
        deletes.push(new_di_key);
        deletes.push(BtrfsKey::new(new_parent, format::DIR_INDEX_KEY, *t_index));
        deletes.push(BtrfsKey::new(*t_ino, format::INODE_REF_KEY, new_parent));
        deletes.push(BtrfsKey::new(*t_ino, format::INODE_ITEM_KEY, 0));
        for off in ed_offsets {
            deletes.push(BtrfsKey::new(*t_ino, format::EXTENT_DATA_KEY, *off));
        }
    }
    for key in &deletes {
        let slot = leaf_find(&fs_leaf, key)?.ok_or(FsError::NotFound)?;
        leaf_delete(&mut fs_leaf, slot)?;
    }

    // Add the entry under the new parent + the moved inode's new INODE_REF.
    let di = dir_item_body(child_ino, gen, ftype, new_bytes);
    leaf_insert_sorted(&mut fs_leaf, &new_di_key, &di)?;
    leaf_insert_sorted(
        &mut fs_leaf,
        &BtrfsKey::new(new_parent, format::DIR_INDEX_KEY, new_index),
        &di,
    )?;
    let iref = inode_ref(new_index, new_bytes);
    leaf_insert_sorted(
        &mut fs_leaf,
        &BtrfsKey::new(child_ino, format::INODE_REF_KEY, new_parent),
        &iref,
    )?;

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: FsChange::Whole {
                content: fs_leaf,
                old_blocks: fs_old_blocks,
            },
            freed_data,
            new_data: Vec::new(),
            data_used_delta: -(freed_bytes as i64),
        },
    )
    .await?;
    Ok(())
}

/// Create a hard link `new_name` in directory `target_parent` to the inode that
/// `old_name` names in directory `source_parent` (both in the default subvolume)
/// via one COW mini-transaction: a new DIR_ITEM + DIR_INDEX in the target dir, an
/// added `INODE_REF` entry (appended to the existing item when the inode already
/// links into that dir, else a fresh item), the inode's `nlink` bumped, and the
/// target dir's `i_size` grown.
///
/// Scope (else the noted error): default subvolume, single leaf; the source must
/// not be a directory (`PermissionDenied` — hard-linking a directory is EPERM),
/// reached by a non-colliding `DIR_ITEM`; `new_name` must be free and not collide
/// in the target's `DIR_ITEM` hash space.
pub async fn link_node<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    source_parent: u64,
    target_parent: u64,
    old_name: &str,
    new_name: &str,
) -> Result<(), FsError> {
    let old_bytes = old_name.as_bytes();
    let new_bytes = new_name.as_bytes();
    for n in [old_name, new_name] {
        if n.is_empty() || n.len() > 255 || n.contains('/') || n == "." || n == ".." {
            return Err(FsError::InvalidData);
        }
    }

    let (fs_root, _) = vol.fs_tree_root();
    let (mut fs_leaf, fs_old_blocks) = read_fs_oversized(vol, fs_root).await?;

    // Resolve the source; hard links to directories are forbidden.
    let old_di_key = BtrfsKey::new(
        source_parent,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(old_bytes)),
    );
    let old_di_slot = leaf_find(&fs_leaf, &old_di_key)?.ok_or(FsError::NotFound)?;
    let old_entries = decode_dir_items(leaf_item_data(&fs_leaf, old_di_slot)?)?;
    if old_entries.len() != 1 {
        return Err(FsError::Unsupported);
    }
    let entry = &old_entries[0];
    if entry.name != old_name {
        return Err(FsError::NotFound);
    }
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported);
    }
    if entry.ftype == format::FT_DIR {
        return Err(FsError::PermissionDenied); // EPERM: no hard links to directories
    }
    let child_ino = entry.location.objectid;
    let child_ftype = entry.ftype;

    // The destination name must be free (no overwrite; also rejects a collision).
    let new_di_key = BtrfsKey::new(
        target_parent,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(new_bytes)),
    );
    if leaf_find(&fs_leaf, &new_di_key)?.is_some() {
        return Err(FsError::Unsupported);
    }

    let new_index = next_dir_index(&fs_leaf, target_parent)?;
    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    // Bump the linked inode's nlink (in place); stamp its transid.
    let ci_slot = leaf_find(
        &fs_leaf,
        &BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
    )?
    .ok_or(FsError::NotFound)?;
    let mut cinode = leaf_item_data(&fs_leaf, ci_slot)?.to_vec();
    let nlink = format::le32(&cinode, 40)?;
    cinode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    cinode[40..44].copy_from_slice(&(nlink + 1).to_le_bytes());
    leaf_replace_inplace(&mut fs_leaf, ci_slot, &cinode)?;

    // Grow the target dir's i_size by the new name (counted twice); transid+seq.
    let pslot = leaf_find(
        &fs_leaf,
        &BtrfsKey::new(target_parent, format::INODE_ITEM_KEY, 0),
    )?
    .ok_or(FsError::NotFound)?;
    let mut pinode = leaf_item_data(&fs_leaf, pslot)?.to_vec();
    let psize = le64(&pinode, 16)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes());
    pinode[16..24].copy_from_slice(&(psize + 2 * new_bytes.len() as u64).to_le_bytes());
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes());
    leaf_replace_inplace(&mut fs_leaf, pslot, &pinode)?;

    // Add the INODE_REF entry: append to the existing (child, INODE_REF, parent)
    // item if the inode already links into this dir, else insert a fresh item.
    let ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, target_parent);
    let entry_bytes = inode_ref(new_index, new_bytes);
    if let Some(slot) = leaf_find(&fs_leaf, &ref_key)? {
        let mut body = leaf_item_data(&fs_leaf, slot)?.to_vec();
        body.extend_from_slice(&entry_bytes);
        leaf_delete(&mut fs_leaf, slot)?;
        leaf_insert_sorted(&mut fs_leaf, &ref_key, &body)?;
    } else {
        leaf_insert_sorted(&mut fs_leaf, &ref_key, &entry_bytes)?;
    }

    // Add the directory entries pointing at the linked inode.
    let di = dir_item_body(child_ino, gen, child_ftype, new_bytes);
    leaf_insert_sorted(&mut fs_leaf, &new_di_key, &di)?;
    leaf_insert_sorted(
        &mut fs_leaf,
        &BtrfsKey::new(target_parent, format::DIR_INDEX_KEY, new_index),
        &di,
    )?;

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: FsChange::Whole {
                content: fs_leaf,
                old_blocks: fs_old_blocks,
            },
            freed_data: Vec::new(),
            new_data: Vec::new(),
            data_used_delta: 0,
        },
    )
    .await?;
    Ok(())
}

/// Build an `XATTR_ITEM`'s `btrfs_dir_item` body: a zeroed location key, transid,
/// `data_len = value.len()`, `name_len`, the `BTRFS_FT_XATTR` type byte, then the
/// attribute name followed by its value.
fn xattr_entry(gen: u64, name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 30 + name.len() + value.len()];
    // location disk_key @0..17 = 0 (unused for xattrs)
    v[17..25].copy_from_slice(&gen.to_le_bytes()); // transid
    v[25..27].copy_from_slice(&(value.len() as u16).to_le_bytes()); // data_len
    v[27..29].copy_from_slice(&(name.len() as u16).to_le_bytes()); // name_len
    v[29] = format::FT_XATTR; // type
    v[30..30 + name.len()].copy_from_slice(name);
    v[30 + name.len()..].copy_from_slice(value);
    v
}

/// Run a metadata-only mutation of the fs leaf (no data extents, no checksums) as
/// a COW mini-transaction: read the fs tree as one logical leaf, hand it and the
/// new generation to `edit`, then commit (which reads/re-packs the other trees).
async fn commit_fs_edit<B, F>(vol: &BtrfsVolume<B>, edit: F) -> Result<(), FsError>
where
    B: BlockDevice + 'static,
    F: FnOnce(&mut Vec<u8>, u64) -> Result<(), FsError>,
{
    let (fs_root, _) = vol.fs_tree_root();
    let (mut fs_leaf, fs_old_blocks) = read_fs_oversized(vol, fs_root).await?;

    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    edit(&mut fs_leaf, gen)?;

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: FsChange::Whole {
                content: fs_leaf,
                old_blocks: fs_old_blocks,
            },
            freed_data: Vec::new(),
            new_data: Vec::new(),
            data_used_delta: 0,
        },
    )
    .await
}

/// Set (create or replace) extended attribute `name` = `value` on inode `ino`
/// (default subvolume). `flags` honours Linux `XATTR_CREATE` (1) / `XATTR_REPLACE`
/// (2). Attributes sharing a name hash coexist in one `XATTR_ITEM` body, so the
/// item is rebuilt preserving the others.
pub async fn set_xattr_item<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    name: &str,
    value: &[u8],
    flags: u32,
) -> Result<(), FsError> {
    let name_bytes = name.as_bytes();
    if name.is_empty() || name_bytes.len() > 255 {
        return Err(FsError::InvalidData);
    }
    const XATTR_CREATE: u32 = 1;
    const XATTR_REPLACE: u32 = 2;
    let key = BtrfsKey::new(
        ino,
        format::XATTR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );

    commit_fs_edit(vol, move |fs_leaf, gen| {
        let existing = leaf_find(fs_leaf, &key)?;
        let mut body = Vec::new();
        let mut had_name = false;
        if let Some(slot) = existing {
            for e in decode_dir_items(leaf_item_data(fs_leaf, slot)?)? {
                if e.name == name {
                    had_name = true; // dropped here, re-added with the new value below
                } else {
                    body.extend_from_slice(&xattr_entry(gen, e.name.as_bytes(), &e.value));
                }
            }
        }
        if flags & XATTR_CREATE != 0 && had_name {
            return Err(FsError::InvalidData); // exists, CREATE requested (EEXIST)
        }
        if flags & XATTR_REPLACE != 0 && !had_name {
            return Err(FsError::NotFound); // absent, REPLACE requested (ENODATA)
        }
        body.extend_from_slice(&xattr_entry(gen, name_bytes, value));
        if let Some(slot) = existing {
            leaf_delete(fs_leaf, slot)?;
        }
        leaf_insert_sorted(fs_leaf, &key, &body)
    })
    .await
}

/// Remove extended attribute `name` from inode `ino` (default subvolume). Deletes
/// the `XATTR_ITEM`, or rebuilds it without this name when others share its hash.
pub async fn remove_xattr_item<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    name: &str,
) -> Result<(), FsError> {
    let name_bytes = name.as_bytes();
    if name.is_empty() {
        return Err(FsError::InvalidData);
    }
    let key = BtrfsKey::new(
        ino,
        format::XATTR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );

    commit_fs_edit(vol, move |fs_leaf, gen| {
        let slot = leaf_find(fs_leaf, &key)?.ok_or(FsError::NotFound)?;
        let entries = decode_dir_items(leaf_item_data(fs_leaf, slot)?)?;
        if !entries.iter().any(|e| e.name == name) {
            return Err(FsError::NotFound); // ENODATA
        }
        let mut body = Vec::new();
        for e in &entries {
            if e.name != name {
                body.extend_from_slice(&xattr_entry(gen, e.name.as_bytes(), &e.value));
            }
        }
        leaf_delete(fs_leaf, slot)?;
        if !body.is_empty() {
            leaf_insert_sorted(fs_leaf, &key, &body)?;
        }
        Ok(())
    })
    .await
}

/// Grow the filesystem by allocating one new mixed (DATA|METADATA, SINGLE) chunk
/// at the end of the device, creating its block group, and threading the change
/// through the chunk tree (new `CHUNK_ITEM` + bumped `DEV_ITEM`), device tree (new
/// `DEV_EXTENT`), extent tree (new `BLOCK_GROUP_ITEM`), free-space tree (the new
/// block group's free space), and root tree — one COW mini-transaction.
///
/// Every one of those trees may be **multi-leaf**: each is read as one logical
/// leaf, edited, then re-packed into as many real leaves as it needs under an
/// internal root ([`pack_tree_at`]). New chunk-tree blocks are placed in the
/// **system chunk** (the chunk tree is read from `sys_chunk_array` before any
/// other chunk is mapped, so it must stay reachable there); the dev/extent/root/
/// free-space blocks are placed at the **start of the new chunk**, so the commit
/// is writable even when the old chunks are full, and the rest of the new chunk is
/// free space. Because the extent tree records its own new blocks, the extent and
/// free-space leaf counts are resolved by the same fixed point [`commit_txn`]
/// uses. `NoSpace` when the device (or system chunk) has no room.
pub async fn grow_add_chunk<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> Result<(), FsError> {
    let sb = vol.superblock();
    let (root_tree, _) = vol.root_tree_root();
    let old_chunk = sb.chunk_root;
    let old_dev = roots::find_root(vol, root_tree, format::DEV_TREE_OBJECTID)
        .await?
        .0;
    let old_ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    let old_fst = roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID)
        .await?
        .0;

    // Read every tree this grow COWs as one oversized logical leaf (any height).
    let (mut chunk_logical, chunk_old) = read_fs_oversized(vol, old_chunk).await?;
    let (mut dev_logical, dev_old) = read_fs_oversized(vol, old_dev).await?;
    let (ext_base0, ext_old) = read_fs_oversized(vol, old_ext).await?;
    let (mut root_logical, root_old) = read_fs_oversized(vol, root_tree).await?;
    let (fst_base0, fst_old) = read_fs_oversized(vol, old_fst).await?;

    // ── Locate the logical/physical high-water and a template chunk item ─
    let mut logical_hw = 0u64;
    let mut template: Option<Vec<u8>> = None; // an 80-byte DATA|METADATA CHUNK_ITEM
    for i in 0..nritems(&chunk_logical)? as usize {
        let k = leaf_item_key(&chunk_logical, i)?;
        if k.item_type != format::CHUNK_ITEM_KEY {
            continue;
        }
        let body = leaf_item_data(&chunk_logical, i)?;
        logical_hw = logical_hw.max(k.offset.saturating_add(le64(body, 0)?));
        if le64(body, 24)? & format::BLOCK_GROUP_DATA != 0 && body.len() >= 80 {
            template = Some(body.to_vec());
        }
    }
    let template = template.ok_or(FsError::Unsupported)?;

    // Physical high-water + a chunk_tree_uuid template from the device extents.
    let mut physical_hw = 0u64;
    let mut chunk_tree_uuid = [0u8; 16];
    for i in 0..nritems(&dev_logical)? as usize {
        let k = leaf_item_key(&dev_logical, i)?;
        if k.item_type != format::DEV_EXTENT_KEY {
            continue;
        }
        let body = leaf_item_data(&dev_logical, i)?;
        physical_hw = physical_hw.max(k.offset.saturating_add(le64(body, 24)?));
        chunk_tree_uuid.copy_from_slice(&body[32..48]);
    }

    // ── Size the new chunk to what remains on the device, skipping the
    //    reserved band around any 64 MiB / 256 GiB superblock mirror ─────
    const STRIPE_LEN: u64 = 65536;
    const MAX_CHUNK: u64 = 8 * 1024 * 1024;
    let (new_physical, avail) = chunk_span_avoiding_supers(physical_hw, sb.total_bytes);
    let chunk_size = (avail.min(MAX_CHUNK) / STRIPE_LEN) * STRIPE_LEN;
    if chunk_size < STRIPE_LEN {
        return Err(FsError::NoSpace); // device full
    }
    let new_logical = logical_hw;
    let gen = sb.generation + 1;
    let nodesize = vol.nodesize() as u64;
    let ns = vol.nodesize();

    // System-chunk arena for the new chunk-tree blocks: past the highest live
    // metadata block already in the system group.
    let (sys_start, sys_len) =
        block_group_of(&ext_base0, old_chunk)?.ok_or(FsError::InvalidData)?;
    let mut sys_hw = sys_start;
    for i in 0..nritems(&ext_base0)? as usize {
        let k = leaf_item_key(&ext_base0, i)?;
        if k.item_type == format::METADATA_ITEM_KEY
            && k.objectid >= sys_start
            && k.objectid < sys_start + sys_len
        {
            sys_hw = sys_hw.max(k.objectid + nodesize);
        }
    }
    let sys_limit = sys_start + sys_len;
    let new_limit = new_logical + chunk_size;

    // ── Chunk tree: new CHUNK_ITEM + bump the DEV_ITEM's bytes_used ─────
    let mut chunk_item = template.clone();
    chunk_item[0..8].copy_from_slice(&chunk_size.to_le_bytes()); // length
    chunk_item[56..64].copy_from_slice(&new_physical.to_le_bytes()); // stripe 0 physical
    leaf_insert_sorted(
        &mut chunk_logical,
        &BtrfsKey::new(
            format::FIRST_CHUNK_TREE_OBJECTID,
            format::CHUNK_ITEM_KEY,
            new_logical,
        ),
        &chunk_item,
    )?;
    let di_slot = leaf_find(
        &chunk_logical,
        &BtrfsKey::new(format::DEV_ITEMS_OBJECTID, format::DEV_ITEM_KEY, 1),
    )?
    .ok_or(FsError::InvalidData)?;
    let mut dev_item = leaf_item_data(&chunk_logical, di_slot)?.to_vec();
    let dev_used = le64(&dev_item, 16)? + chunk_size;
    dev_item[16..24].copy_from_slice(&dev_used.to_le_bytes());
    leaf_replace_inplace(&mut chunk_logical, di_slot, &dev_item)?;

    // ── Device tree: new DEV_EXTENT for the physical range ─────────────
    let mut dev_extent = alloc::vec![0u8; 48];
    dev_extent[0..8].copy_from_slice(&format::CHUNK_TREE_OBJECTID.to_le_bytes());
    dev_extent[8..16].copy_from_slice(&format::FIRST_CHUNK_TREE_OBJECTID.to_le_bytes());
    dev_extent[16..24].copy_from_slice(&new_logical.to_le_bytes());
    dev_extent[24..32].copy_from_slice(&chunk_size.to_le_bytes());
    dev_extent[32..48].copy_from_slice(&chunk_tree_uuid);
    leaf_insert_sorted(
        &mut dev_logical,
        &BtrfsKey::new(
            format::DEV_ITEMS_OBJECTID,
            format::DEV_EXTENT_KEY,
            new_physical,
        ),
        &dev_extent,
    )?;

    // ── Extent tree base: add the new BLOCK_GROUP_ITEM (used charged later) ─
    let mut ext_base = ext_base0;
    let mut bg = alloc::vec![0u8; 24];
    bg[8..16].copy_from_slice(&format::FIRST_CHUNK_TREE_OBJECTID.to_le_bytes()); // chunk_objectid
    bg[16..24]
        .copy_from_slice(&(format::BLOCK_GROUP_DATA | format::BLOCK_GROUP_METADATA).to_le_bytes());
    leaf_insert_sorted(
        &mut ext_base,
        &BtrfsKey::new(new_logical, format::BLOCK_GROUP_ITEM_KEY, chunk_size),
        &bg,
    )?;

    // ── Free-space tree base: FREE_SPACE_INFO for the new group ────────
    let mut fst_base = fst_base0;
    let mut info = alloc::vec![0u8; 8];
    info[0..4].copy_from_slice(&1u32.to_le_bytes()); // extent_count (one free run)
    leaf_insert_sorted(
        &mut fst_base,
        &BtrfsKey::new(new_logical, format::FREE_SPACE_INFO_KEY, chunk_size),
        &info,
    )?;

    // Fixed groupings: chunk/dev content and the root tree's size are settled.
    let chunk_groups = group_items(vol, &chunk_logical)?;
    let dev_groups = group_items(vol, &dev_logical)?;
    let root_groups = group_items(vol, &root_logical)?;
    let chunk_nc = tree_block_count(chunk_groups.len(), ns);
    let dev_nc = tree_block_count(dev_groups.len(), ns);
    let root_nc = tree_block_count(root_groups.len(), ns);

    // Every old block across every COWed tree is returned to free space.
    let mut freed_meta: Vec<(u64, u8)> = chunk_old;
    freed_meta.extend(dev_old);
    freed_meta.extend(ext_old);
    freed_meta.extend(root_old);
    freed_meta.extend(fst_old);

    // ── Fixed point over the extent/free-space leaf counts ─────────────
    // Chunk-tree blocks come from the system arena; dev/ext/root/free-space from
    // the new chunk. The new group's used prefix (hence its free run) grows with
    // the extent/free-space leaf counts, so they are resolved together.
    #[allow(clippy::type_complexity)]
    struct Grown {
        chunk_addrs: Vec<u64>,
        dev_addrs: Vec<u64>,
        ext_addrs: Vec<u64>,
        root_addrs: Vec<u64>,
        fst_addrs: Vec<u64>,
        new_meta: Vec<(u64, u64, u8)>,
        ext_final: Vec<u8>,
        ext_groups: Vec<(usize, usize)>,
        fst_final: Vec<u8>,
        fst_groups: Vec<(usize, usize)>,
    }
    let mut grown: Option<Grown> = None;
    let mut ext_leaves = 1usize;
    let mut fst_leaves = 1usize;

    for _ in 0..8 {
        let mut sc = sys_hw;
        let mut nc = new_logical;
        let chunk_addrs = take_nodes(&mut sc, sys_limit, chunk_nc, nodesize)?;
        let dev_addrs = take_nodes(&mut nc, new_limit, dev_nc, nodesize)?;
        let ext_addrs = take_nodes(
            &mut nc,
            new_limit,
            ext_leaves + usize::from(ext_leaves > 1),
            nodesize,
        )?;
        let root_addrs = take_nodes(&mut nc, new_limit, root_nc, nodesize)?;
        let fst_addrs = take_nodes(
            &mut nc,
            new_limit,
            fst_leaves + usize::from(fst_leaves > 1),
            nodesize,
        )?;
        // The new group's used prefix = every new block placed in the new chunk.
        let newbg_used = (dev_addrs.len() + ext_addrs.len() + root_addrs.len() + fst_addrs.len())
            as u64
            * nodesize;

        let mut new_meta: Vec<(u64, u64, u8)> = Vec::new();
        collect_tree_meta(
            &chunk_addrs,
            chunk_groups.len(),
            ns,
            format::CHUNK_TREE_OBJECTID,
            &mut new_meta,
        );
        collect_tree_meta(
            &dev_addrs,
            dev_groups.len(),
            ns,
            format::DEV_TREE_OBJECTID,
            &mut new_meta,
        );
        collect_tree_meta(
            &ext_addrs,
            ext_leaves,
            ns,
            format::EXTENT_TREE_OBJECTID,
            &mut new_meta,
        );
        collect_tree_meta(
            &root_addrs,
            root_groups.len(),
            ns,
            format::ROOT_TREE_OBJECTID,
            &mut new_meta,
        );
        collect_tree_meta(
            &fst_addrs,
            fst_leaves,
            ns,
            format::FREE_SPACE_TREE_OBJECTID,
            &mut new_meta,
        );

        // Extent tree with this iteration's metadata items.
        let mut ext_final = ext_base.clone();
        for &(blk, lvl) in &freed_meta {
            if let Some(s) = leaf_find(
                &ext_final,
                &BtrfsKey::new(blk, format::METADATA_ITEM_KEY, u64::from(lvl)),
            )? {
                leaf_delete(&mut ext_final, s)?;
            }
        }
        for &(addr, owner, lvl) in &new_meta {
            leaf_insert_sorted(
                &mut ext_final,
                &BtrfsKey::new(addr, format::METADATA_ITEM_KEY, u64::from(lvl)),
                &ext_item_meta(gen, owner),
            )?;
        }
        let ext_groups = group_items(vol, &ext_final)?;

        // Free-space tree: the new group's free run, the carved system blocks,
        // and every freed old block returned to its group.
        let mut fst_final = fst_base.clone();
        leaf_insert_sorted(
            &mut fst_final,
            &BtrfsKey::new(
                new_logical + newbg_used,
                format::FREE_SPACE_EXTENT_KEY,
                chunk_size - newbg_used,
            ),
            &[],
        )?;
        for &a in &chunk_addrs {
            fst_mark_used(
                &mut fst_final,
                vol.sectorsize() as u64,
                sys_start,
                sys_len,
                a,
                nodesize,
            )?;
        }
        for &(blk, _) in &freed_meta {
            let (s, l) = block_group_of(&ext_final, blk)?.ok_or(FsError::InvalidData)?;
            fst_mark_free(&mut fst_final, vol.sectorsize() as u64, s, l, blk, nodesize)?;
        }
        let fst_groups = group_items(vol, &fst_final)?;

        if ext_groups.len() == ext_leaves && fst_groups.len() == fst_leaves {
            grown = Some(Grown {
                chunk_addrs,
                dev_addrs,
                ext_addrs,
                root_addrs,
                fst_addrs,
                new_meta,
                ext_final,
                ext_groups,
                fst_final,
                fst_groups,
            });
            break;
        }
        ext_leaves = ext_groups.len();
        fst_leaves = fst_groups.len();
    }
    let Grown {
        chunk_addrs,
        dev_addrs,
        ext_addrs,
        root_addrs,
        fst_addrs,
        new_meta,
        mut ext_final,
        ext_groups,
        fst_final,
        fst_groups,
    } = grown.ok_or(FsError::NoSpace)?;

    // ── Block-group `used`: charge each new block, uncharge each freed one ──
    for &(addr, _, _) in &new_meta {
        block_group_add_used(&mut ext_final, addr, nodesize as i64)?;
    }
    for &(blk, _) in &freed_meta {
        block_group_add_used(&mut ext_final, blk, -(nodesize as i64))?;
    }

    // ── Root tree: repoint the device/extent/free-space ROOT_ITEMs ─────
    let (chunk_root_addr, _) = tree_root_addr(&chunk_addrs, chunk_groups.len(), ns);
    let (dev_root_addr, dev_lvl) = tree_root_addr(&dev_addrs, dev_groups.len(), ns);
    let (ext_root_addr, ext_lvl) = tree_root_addr(&ext_addrs, ext_groups.len(), ns);
    let (root_root_addr, _) = tree_root_addr(&root_addrs, root_groups.len(), ns);
    let (fst_root_addr, fst_lvl) = tree_root_addr(&fst_addrs, fst_groups.len(), ns);
    for (owner, new, lvl) in [
        (format::DEV_TREE_OBJECTID, dev_root_addr, dev_lvl),
        (format::EXTENT_TREE_OBJECTID, ext_root_addr, ext_lvl),
        (format::FREE_SPACE_TREE_OBJECTID, fst_root_addr, fst_lvl),
    ] {
        let slot = leaf_find_by_type(&root_logical, owner, format::ROOT_ITEM_KEY)?
            .ok_or(FsError::NotFound)?;
        let mut ri = leaf_item_data(&root_logical, slot)?.to_vec();
        ri[160..168].copy_from_slice(&gen.to_le_bytes());
        ri[176..184].copy_from_slice(&new.to_le_bytes());
        ri[238] = lvl;
        if ri.len() >= 247 {
            ri[239..247].copy_from_slice(&gen.to_le_bytes());
        }
        leaf_replace_inplace(&mut root_logical, slot, &ri)?;
    }

    // ── Pack every tree, publish the chunk mapping, write, flip the super ──
    let mut nodes: Vec<(u64, Vec<u8>)> = Vec::new();
    nodes.extend(pack_tree_at(vol, &chunk_logical, &chunk_groups, &chunk_addrs, gen)?.0);
    nodes.extend(pack_tree_at(vol, &dev_logical, &dev_groups, &dev_addrs, gen)?.0);
    nodes.extend(pack_tree_at(vol, &ext_final, &ext_groups, &ext_addrs, gen)?.0);
    nodes.extend(pack_tree_at(vol, &root_logical, &root_groups, &root_addrs, gen)?.0);
    nodes.extend(pack_tree_at(vol, &fst_final, &fst_groups, &fst_addrs, gen)?.0);

    vol.add_chunk_mapping(new_logical, chunk_size, 1, new_physical);
    for (addr, buf) in &nodes {
        vol.write_logical(*addr, buf).await?;
    }

    let mut raw = vol.read_raw_superblock().await?;
    raw[72..80].copy_from_slice(&gen.to_le_bytes()); // generation
    raw[80..88].copy_from_slice(&root_root_addr.to_le_bytes()); // root
    raw[88..96].copy_from_slice(&chunk_root_addr.to_le_bytes()); // chunk_root
    raw[164..172].copy_from_slice(&gen.to_le_bytes()); // chunk_root_generation
                                                       // Embedded dev_item.bytes_used (dev_item@201, bytes_used@+16).
    raw[217..225].copy_from_slice(&dev_used.to_le_bytes());
    let csum = block_csum(&raw[format::CSUM_SIZE..format::SUPERBLOCK_SIZE]);
    raw[0..4].copy_from_slice(&csum.to_le_bytes());
    for b in &mut raw[4..format::CSUM_SIZE] {
        *b = 0;
    }
    vol.flush().await;
    vol.write_superblock(&raw).await?;
    vol.commit_chunk_root(chunk_root_addr, root_root_addr, gen);
    Ok(())
}
