//! Copy-on-write mutations: file writes (overwrite / partial / append / grow)
//! and namespace operations (`create` / `unlink`) in the mounted subvolume.
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
//! Scope: a regular file in the mounted writable subvolume with any number of
//! existing extents (exclusive, shared, partial, hole or inline). A write closes
//! its sector-aligned window over intersected file extents, applies the new bytes
//! and re-tiles only that window into fresh extents of at most 128 KiB. Exact
//! delayed backref drops reclaim an old physical extent only after its final
//! snapshot/reflink reference disappears. Per write it:
//!
//! 1. allocates + writes the new data extents, and their per-sector selected
//!    **data checksums** (updated in the CSUM tree; old csums removed);
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

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::allocator::Allocator;
use crate::btree::{
    self, internal_blockptr, internal_child_slot, internal_key, leaf_item_data, leaf_item_key,
    leaf_item_span, leaf_lower_bound, level, nritems, HEADER_SIZE,
};
use crate::checksum::name_hash;
use crate::dir::{append_dir_item, decode_dir_items, find_dir_item, remove_dir_item, DirEntry};
use crate::format::{self, le64, BtrfsKey};
use crate::inode::InodeItem;
use crate::roots;
use crate::volume::BtrfsVolume;

// Header field offsets rewritten when a node is stamped.
const HDR_BYTENR: usize = 48;
const HDR_GENERATION: usize = 80;
/// Node header `owner` field (the objectid of the tree the node belongs to).
const HDR_OWNER: usize = 88;

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

/// Stamp a node buffer with `addr`, `gen`, and the filesystem's selected
/// checksum in place (no allocation, no write).
pub(crate) fn stamp_node(
    buf: &mut [u8],
    addr: u64,
    gen: u64,
    csum_type: u16,
) -> Result<(), FsError> {
    buf[HDR_BYTENR..HDR_BYTENR + 8].copy_from_slice(&addr.to_le_bytes());
    buf[HDR_GENERATION..HDR_GENERATION + 8].copy_from_slice(&gen.to_le_bytes());
    crate::checksum::stamp_block(csum_type, buf)
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

/// Identity of one file reference to a physical data extent. Multiple roots or
/// inodes may name the same `(bytenr, len)`; the extent item's aggregate `refs`
/// is the sum of their individual `count` fields.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct DataRefId {
    bytenr: u64,
    len: u64,
    ref_root: u64,
    objectid: u64,
    offset: u64,
}

fn data_ref_hash(id: &DataRefId) -> u64 {
    let mut high = !0u32;
    let mut low = !0u32;
    high = crate::checksum::crc32c(high, &id.ref_root.to_le_bytes());
    low = crate::checksum::crc32c(low, &id.objectid.to_le_bytes());
    low = crate::checksum::crc32c(low, &id.offset.to_le_bytes());
    (u64::from(high) << 31) ^ u64::from(low)
}

fn inline_ref_size(kind: u8) -> Result<usize, FsError> {
    match kind {
        TREE_BLOCK_REF_KEY | 182 => Ok(9), // TREE_BLOCK_REF / SHARED_BLOCK_REF
        EXTENT_DATA_REF_KEY => Ok(29),
        184 => Ok(13), // SHARED_DATA_REF
        _ => Err(FsError::Unsupported),
    }
}

/// Apply one delayed data-ref delta to an `EXTENT_ITEM`. Returns `None` when
/// the aggregate reference count reaches zero and the physical extent can be
/// reclaimed. Inline refs retain the kernel-required ordering: type ascending,
/// then data-ref hash descending.
fn update_data_ref(body: &[u8], id: &DataRefId, delta: i8) -> Result<Option<Vec<u8>>, FsError> {
    if body.len() < 24 || le64(body, 16)? & EXTENT_FLAG_DATA == 0 || !matches!(delta, -1 | 1) {
        return Err(FsError::InvalidData);
    }
    let mut out = body.to_vec();
    let mut pos = 24usize;
    let mut found: Option<(usize, usize, u32)> = None;
    let mut insert_at = body.len();
    let wanted_hash = data_ref_hash(id);
    while pos < body.len() {
        let kind = body[pos];
        let size = inline_ref_size(kind)?;
        let end = pos.checked_add(size).ok_or(FsError::InvalidData)?;
        if end > body.len() {
            return Err(FsError::InvalidData);
        }
        if delta > 0 && insert_at == body.len() {
            if kind > EXTENT_DATA_REF_KEY {
                insert_at = pos;
            } else if kind == EXTENT_DATA_REF_KEY {
                let existing = DataRefId {
                    bytenr: id.bytenr,
                    len: id.len,
                    ref_root: le64(body, pos + 1)?,
                    objectid: le64(body, pos + 9)?,
                    offset: le64(body, pos + 17)?,
                };
                if data_ref_hash(&existing) < wanted_hash {
                    insert_at = pos;
                }
            }
        }
        if kind == EXTENT_DATA_REF_KEY
            && le64(body, pos + 1)? == id.ref_root
            && le64(body, pos + 9)? == id.objectid
            && le64(body, pos + 17)? == id.offset
        {
            found = Some((pos, size, format::le32(body, pos + 25)?));
            break;
        }
        pos = end;
    }

    let refs = le64(body, 0)?;
    if delta > 0 {
        if let Some((at, _, count)) = found {
            let next = count.checked_add(1).ok_or(FsError::InvalidData)?;
            out[at + 25..at + 29].copy_from_slice(&next.to_le_bytes());
        } else {
            let mut entry = alloc::vec![0u8; 29];
            entry[0] = EXTENT_DATA_REF_KEY;
            entry[1..9].copy_from_slice(&id.ref_root.to_le_bytes());
            entry[9..17].copy_from_slice(&id.objectid.to_le_bytes());
            entry[17..25].copy_from_slice(&id.offset.to_le_bytes());
            entry[25..29].copy_from_slice(&1u32.to_le_bytes());
            out.splice(insert_at..insert_at, entry);
        }
        out[0..8].copy_from_slice(
            &refs
                .checked_add(1)
                .ok_or(FsError::InvalidData)?
                .to_le_bytes(),
        );
        Ok(Some(out))
    } else {
        let (at, size, count) = found.ok_or(FsError::Unsupported)?;
        if refs == 0 || count == 0 {
            return Err(FsError::InvalidData);
        }
        if count > 1 {
            out[at + 25..at + 29].copy_from_slice(&(count - 1).to_le_bytes());
        } else {
            out.drain(at..at + size);
        }
        let remaining = refs - 1;
        if remaining == 0 {
            Ok(None)
        } else {
            out[0..8].copy_from_slice(&remaining.to_le_bytes());
            Ok(Some(out))
        }
    }
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

/// Encode one zlib stream without placing miniz's 64 KiB LZ code buffer on
/// the kernel stack. `compress_to_vec_zlib` constructs `CompressorOxide`
/// locally; that exceeds the aarch64 test-task stack before compression even
/// starts. `Box::default` initializes the compressor in its heap allocation.
pub(crate) fn compress_zlib_heap(input: &[u8], level: u8) -> Result<Vec<u8>, FsError> {
    use miniz_oxide::deflate::core::{
        compress_to_output, CompressorOxide, TDEFLFlush, TDEFLStatus,
    };
    use miniz_oxide::DataFormat;

    let mut compressor = Box::<CompressorOxide>::default();
    compressor.set_format_and_level(DataFormat::Zlib, level);
    let mut output = Vec::new();
    let (status, consumed) =
        compress_to_output(&mut compressor, input, TDEFLFlush::Finish, |chunk| {
            output.extend_from_slice(chunk);
            true
        });
    if status == TDEFLStatus::Done && consumed == input.len() {
        Ok(output)
    } else {
        Err(FsError::InvalidData)
    }
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

/// Write `data` at byte `offset` into file `ino` via COW. Only the sector-aligned
/// write window and the existing extents it intersects are read, freed and
/// re-tiled (each new extent is at most [`MAX_WRITE_EXTENT`]); non-overlapping
/// extents keep their original `EXTENT_DATA`, extent-tree ref and checksums.
///
/// Intersected shared and partial references are read through their
/// `extent_offset`, then dropped by exact `(root, inode, backref-offset)` identity;
/// the backing extent survives while any other reference remains. Recognized
/// zlib/zstd/LZO extents are decompressed by the read phase; zlib is preserved
/// when recompression saves space, while zstd/LZO fall back to uncompressed COW.
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

    let old_size = inode.size;
    let end = offset
        .checked_add(data.len() as u64)
        .ok_or(FsError::InvalidData)?;
    let new_size = old_size.max(end);
    let sectorsize = u64::from(vol.sectorsize());

    // Start with the sectors touched by the write. If that cuts through an
    // existing extent, absorb that entire extent; repeat because widening the
    // window can meet another item. This avoids creating two file references to
    // one backing extent (which would require multi-ref delayed-ref handling).
    let mut rewrite_start = offset & !(sectorsize - 1);
    let mut rewrite_end = align_up(end, sectorsize);
    let extents = btree::collect_for(vol, fs_root, ino, format::EXTENT_DATA_KEY).await?;
    let mut file_ranges: Vec<(u64, u64)> = Vec::with_capacity(extents.len());
    for (key, body) in &extents {
        if body.len() < 21 {
            return Err(FsError::InvalidData);
        }
        let file_len = match body[20] {
            format::FILE_EXTENT_INLINE => le64(body, 8)?,
            format::FILE_EXTENT_REG | format::FILE_EXTENT_PREALLOC => {
                if body.len() < 53 {
                    return Err(FsError::InvalidData);
                }
                le64(body, 45)?
            }
            _ => return Err(FsError::InvalidData),
        };
        file_ranges.push((key.offset, key.offset.saturating_add(file_len)));
    }

    let mut affected = alloc::vec![false; extents.len()];
    loop {
        let mut widened = false;
        for (i, &(start, finish)) in file_ranges.iter().enumerate() {
            if affected[i] || start >= rewrite_end || finish <= rewrite_start {
                continue;
            }
            affected[i] = true;
            let new_start = rewrite_start.min(start & !(sectorsize - 1));
            let new_end = rewrite_end.max(align_up(finish, sectorsize));
            widened |= new_start != rewrite_start || new_end != rewrite_end;
            rewrite_start = new_start;
            rewrite_end = new_end;
        }
        if !widened {
            break;
        }
    }

    // Classify only the intersected extents. Non-overlapping shared/partial
    // extents are deliberately left alone.
    let mut dropped_data: Vec<DataRefId> = Vec::new();
    let mut removed_nbytes = 0u64;
    let mut saw_zlib = false;
    let mut zlib_only = true;
    for (i, (key, body)) in extents.iter().enumerate() {
        if !affected[i] {
            continue;
        }
        // btrfs_file_extent_item: ram_bytes@8, compression@16, type@20,
        // disk_bytenr@21, disk_num_bytes@29, extent_offset@37, num_bytes@45.
        if body[20] == format::FILE_EXTENT_INLINE {
            zlib_only = false;
            removed_nbytes = removed_nbytes
                .checked_add(le64(body, 8)?)
                .ok_or(FsError::InvalidData)?;
            continue; // data lives in the item; no disk extent to free
        }
        let compression = body[16];
        if !matches!(
            compression,
            format::COMPRESS_NONE
                | format::COMPRESS_ZLIB
                | format::COMPRESS_LZO
                | format::COMPRESS_ZSTD
        ) {
            return Err(FsError::Unsupported);
        }
        if compression != format::COMPRESS_NONE && body[20] != format::FILE_EXTENT_REG {
            return Err(FsError::Unsupported);
        }
        let disk_bytenr = le64(body, 21)?;
        if disk_bytenr == 0 {
            continue; // a hole: no disk extent
        }
        saw_zlib |= compression == format::COMPRESS_ZLIB;
        zlib_only &= compression == format::COMPRESS_ZLIB;
        let disk_num = le64(body, 29)?;
        let extent_offset = le64(body, 37)?;
        let backref_offset = key
            .offset
            .checked_sub(extent_offset)
            .ok_or(FsError::InvalidData)?;
        dropped_data.push(DataRefId {
            bytenr: disk_bytenr,
            len: disk_num,
            ref_root: vol.fs_tree_id(),
            objectid: ino,
            offset: backref_offset,
        });
        removed_nbytes = removed_nbytes
            .checked_add(le64(body, 45)?)
            .ok_or(FsError::InvalidData)?;
    }
    // Preserve an existing zlib policy when the complete replacement window is
    // made solely from zlib extents (plus holes). Mixed-codec/uncompressed
    // windows fall back to ordinary extents.
    let emit_zlib = saw_zlib && zlib_only;

    // Read-modify-write only the closed-over window. Bytes past the old EOF and
    // implicit/explicit holes remain zero-filled.
    let rewrite_len = rewrite_end
        .checked_sub(rewrite_start)
        .ok_or(FsError::InvalidData)?;
    let rewrite_len_usize = usize::try_from(rewrite_len).map_err(|_| FsError::InvalidData)?;
    let mut buf = alloc::vec![0u8; rewrite_len_usize];
    if rewrite_start < old_size {
        let old_window_end = rewrite_end.min(old_size);
        let old_window_len =
            usize::try_from(old_window_end - rewrite_start).map_err(|_| FsError::InvalidData)?;
        crate::extent::read_file(
            vol,
            fs_root,
            ino,
            old_size,
            rewrite_start,
            &mut buf[..old_window_len],
        )
        .await?;
    }
    let o = usize::try_from(offset - rewrite_start).map_err(|_| FsError::InvalidData)?;
    buf[o..o + data.len()].copy_from_slice(data);

    let gen = vol.superblock().generation + 1;
    let mut alloc = Allocator::build(vol).await?;

    // ── Tile the content into fresh extents; write each + its checksums ─
    let mut new_data: Vec<DataRef> = Vec::new();
    let mut new_eds: Vec<(BtrfsKey, Vec<u8>)> = Vec::new();
    let mut window_off = 0u64;
    while window_off < rewrite_len {
        let ext_len = (rewrite_len - window_off).min(MAX_WRITE_EXTENT);
        let s = window_off as usize;
        let e = s + ext_len as usize;
        let plain = &buf[s..e];
        let compressed = if emit_zlib {
            let mut encoded = compress_zlib_heap(plain, 6)?;
            let disk_len = align_up(encoded.len() as u64, sectorsize);
            if disk_len < ext_len {
                encoded.resize(disk_len as usize, 0);
                Some(encoded)
            } else {
                None
            }
        } else {
            None
        };
        let (payload, compression) = match &compressed {
            Some(encoded) => (encoded.as_slice(), format::COMPRESS_ZLIB),
            None => (plain, format::COMPRESS_NONE),
        };
        let disk_len = payload.len() as u64;
        let e_data = alloc.alloc_data(vol, disk_len)?;
        vol.write_logical(e_data, payload).await?;
        let csums = crate::csum::compute_csums(vol.csum_type(), payload, sectorsize as usize)?;
        let file_off = rewrite_start + window_off;
        new_data.push(DataRef {
            id: DataRefId {
                bytenr: e_data,
                len: disk_len,
                ref_root: vol.fs_tree_id(),
                objectid: ino,
                offset: file_off,
            },
            csums,
        });
        new_eds.push((
            BtrfsKey::new(ino, format::EXTENT_DATA_KEY, file_off),
            file_extent_reg_encoded(gen, e_data, disk_len, ext_len, compression),
        ));
        window_off += ext_len;
    }

    // ── Path-COW the fs tree: drop only intersected EXTENT_DATA, add the new tiling,
    //    and update the inode (found via a lookup, not a full tree read) —
    //    COWing only the touched paths rather than rebuilding the whole tree. ──
    let mut edits: Vec<Edit> = Vec::new();
    for (i, (key, _)) in extents.iter().enumerate() {
        if affected[i] {
            edits.push(Edit::Delete(*key));
        }
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
    let old_nbytes = le64(&new_inode, 24)?;
    let new_nbytes = old_nbytes
        .checked_sub(removed_nbytes)
        .and_then(|n| n.checked_add(rewrite_len))
        .ok_or(FsError::InvalidData)?;
    new_inode[24..32].copy_from_slice(&new_nbytes.to_le_bytes()); // nbytes
    edits.push(Edit::Upsert(inode_key, new_inode));

    let out = PathCow::new(vol, gen, fs_root, fs_level)
        .await?
        .apply(&mut alloc, &edits)
        .await?;
    let fs = fs_commit_from(out, gen, vol.csum_type())?;

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs,
            dropped_data,
            added_data: Vec::new(),
            new_data,
            root_flags: None,
            extra_trees: Vec::new(),
            root_edits: Vec::new(),
            retired_meta: Vec::new(),
        },
    )
    .await?;
    Ok(data.len())
}

/// Stamp a path-COW's new nodes and package them as an [`FsCommit`].
fn fs_commit_from(out: CowOut, gen: u64, csum_type: u16) -> Result<FsCommit, FsError> {
    let new_blocks: Vec<(u64, u8)> = out.nodes.iter().map(|&(a, _, l)| (a, l)).collect();
    let mut nodes = Vec::with_capacity(out.nodes.len());
    for (addr, mut buf, _lvl) in out.nodes {
        stamp_node(&mut buf, addr, gen, csum_type)?;
        nodes.push((addr, buf));
    }
    Ok(FsCommit {
        nodes,
        new_blocks,
        freed: out.freed,
        root: out.root_addr,
        level: out.root_level,
    })
}

// ── Shared COW mini-transaction ────────────────────────────────────

/// Path-COW the fs tree with `edits` and commit, moving data-ref deltas
/// through the extent + csum trees. The namespace mutations funnel through here:
/// each touches only a handful of keys, so only their root-to-leaf paths are
/// rewritten (`O(log N)`), never the whole tree.
async fn commit_fs_edits<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    gen: u64,
    mut alloc: Allocator,
    edits: &[Edit],
    dropped_data: Vec<DataRefId>,
    new_data: Vec<DataRef>,
) -> Result<(), FsError> {
    let (fs_root, fs_level) = vol.fs_tree_root();
    let out = PathCow::new(vol, gen, fs_root, fs_level)
        .await?
        .apply(&mut alloc, edits)
        .await?;
    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: fs_commit_from(out, gen, vol.csum_type())?,
            dropped_data,
            added_data: Vec::new(),
            new_data,
            root_flags: None,
            extra_trees: Vec::new(),
            root_edits: Vec::new(),
            retired_meta: Vec::new(),
        },
    )
    .await
}

/// On-disk size of one internal `struct btrfs_key_ptr` (key + blockptr + gen).
const KEY_PTR_SIZE: usize = format::DISK_KEY_SIZE + 16;

/// A data extent recorded into the extent tree as an `EXTENT_ITEM` +
/// `EXTENT_DATA_REF{root, objectid, offset, count=1}`, with the per-sector
/// selected-algorithm `csums` the csum tree records for it. `offset` is the
/// extent's position in the file (its `EXTENT_DATA` key offset).
struct DataRef {
    id: DataRefId,
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

/// A second tree created or path-COWed by the same transaction as the mounted
/// fs tree. Subvolume creation uses this for the new empty fs tree and, when
/// present, the UUID tree update.
struct ExtraTree {
    owner: u64,
    commit: FsCommit,
}

/// One mutation's fs-tree edit plus the data-extent bookkeeping the
/// extent/free-space/csum trees must reflect. `commit_txn` reads the
/// extent/csum/root/free-space trees itself, applies the data + metadata deltas,
/// path-COWs the extent tree, re-packs csum/root/free-space, allocates every new
/// block, stamps them, and flips the superblock.
struct Txn {
    /// The fs tree's edit: a pre-built path COW of only the touched paths, whose
    /// nodes were already allocated from the same allocator `commit_txn` uses.
    fs: FsCommit,
    /// Existing data references removed by the mutation. The physical extent
    /// and its csums are reclaimed only when the aggregate refcount reaches 0.
    dropped_data: Vec<DataRefId>,
    /// References added to already-allocated data extents (snapshot/reflink).
    added_data: Vec<DataRefId>,
    /// Data extents whose `EXTENT_ITEM` + csums are added.
    new_data: Vec<DataRef>,
    /// Replacement `btrfs_root_item.flags` for the mounted subvolume. This is a
    /// root-tree-only administration transaction: the fs tree itself remains
    /// byte-for-byte unchanged.
    root_flags: Option<u64>,
    /// Additional tree commits whose metadata refs and root items advance in
    /// the same superblock generation as the mounted fs-tree edit.
    extra_trees: Vec<ExtraTree>,
    /// Root-tree namespace edits (subvolume ROOT_ITEM plus forward/back refs).
    root_edits: Vec<Edit>,
    /// Exclusively-owned metadata trees removed by this transaction.
    retired_meta: Vec<(u64, u8)>,
}

/// Persist replacement on-disk flags for the explicitly mounted subvolume.
/// This deliberately builds a root-tree-only transaction: changing read-only
/// state must not COW or advance the unchanged fs tree's root item.
pub(crate) async fn set_subvol_flags<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    flags: u64,
) -> Result<(), FsError> {
    let gen = vol
        .superblock()
        .generation
        .checked_add(1)
        .ok_or(FsError::InvalidData)?;
    let alloc = Allocator::build(vol).await?;
    let (root, level) = vol.fs_tree_root();
    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: FsCommit {
                nodes: Vec::new(),
                new_blocks: Vec::new(),
                freed: Vec::new(),
                root,
                level,
            },
            dropped_data: Vec::new(),
            added_data: Vec::new(),
            new_data: Vec::new(),
            root_flags: Some(flags),
            extra_trees: Vec::new(),
            root_edits: Vec::new(),
            retired_meta: Vec::new(),
        },
    )
    .await
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
// possibly into several). They are pure — addresses and checksum stamps are
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
#[derive(Clone)]
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

    /// Re-tile `bufs` in place of the node at `old_addr`: if `old_addr` was made
    /// *this* transaction, its first tile reuses that address (edit in place — no
    /// new allocation, nothing freed); otherwise the old committed block is freed
    /// and every tile is a fresh block. Extra tiles (from a split) are always
    /// fresh. An emptied non-root node is dropped (returns no pointers).
    ///
    /// In-place editing is what makes a batch cheap — the path is COWed once, then
    /// further edits to the same nodes cost nothing — and what lets the extent
    /// tree's delayed-ref loop converge (recording a block into an already-COWed
    /// leaf allocates nothing).
    fn cow_node(
        &mut self,
        alloc: &mut Allocator,
        old_addr: u64,
        bufs: Vec<Vec<u8>>,
        level: u8,
    ) -> Result<Vec<(BtrfsKey, u64, u64)>, FsError> {
        if bufs.len() == 1 && nritems(&bufs[0])? == 0 && (self.root_level > 0 || level > 0) {
            self.retire(old_addr, level); // an emptied non-root node: drop it
            return Ok(Vec::new());
        }
        let reuse = self.pending.contains_key(&old_addr);
        let mut ptrs = Vec::with_capacity(bufs.len());
        for (i, buf) in bufs.into_iter().enumerate() {
            let key = Self::first_key(&buf)?;
            let addr = if i == 0 && reuse {
                self.pending.insert(old_addr, (buf, level)); // edit in place
                old_addr
            } else {
                self.store(alloc, buf, level)?
            };
            ptrs.push((key, addr, self.gen));
        }
        if !reuse {
            self.freed.push((old_addr, level)); // a committed block is replaced
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
        let mut cur_ptrs = self.cow_node(alloc, leaf_addr, new_leaves, 0)?;
        let mut ptr_level = 0u8;

        // Propagate the replacement pointer(s) up the path, re-tiling as needed.
        while let Some((paddr, plevel, mut ptrs, slot)) = path.pop() {
            ptrs.splice(slot..=slot, cur_ptrs.iter().copied());
            if ptrs.is_empty() {
                self.retire(paddr, plevel); // this node emptied out
                cur_ptrs = Vec::new();
                continue;
            }
            let bufs = regroup_internal(&self.header, &ptrs, self.nodesize, plevel);
            cur_ptrs = self.cow_node(alloc, paddr, bufs, plevel)?;
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
/// [`collect_tree_meta`]. Every node's bytenr/generation/checksum is stamped.
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
        stamp_node(&mut leaf, addr, gen, vol.csum_type())?;
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
            stamp_node(&mut node, addr, gen, vol.csum_type())?;
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

/// Read every `BLOCK_GROUP_ITEM` from the extent tree as `(start, len, body)`.
async fn read_block_groups<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ext_root: u64,
) -> Result<Vec<(u64, u64, Vec<u8>)>, FsError> {
    let mut cursor = btree::Cursor::seek(vol, ext_root, &BtrfsKey::new(0, 0, 0)).await?;
    let mut out = Vec::new();
    while let Some((k, body)) = cursor.current()? {
        if k.item_type == format::BLOCK_GROUP_ITEM_KEY {
            out.push((k.objectid, k.offset, body.to_vec()));
        }
        cursor.advance().await?;
    }
    Ok(out)
}

/// Sum every block group's `used` — the definition of the superblock's
/// `bytes_used`. Read from `ext_root` after the extent tree is written so it can
/// never drift from the block groups themselves.
async fn total_block_group_used<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ext_root: u64,
) -> Result<u64, FsError> {
    let mut total = 0u64;
    for (_, _, body) in read_block_groups(vol, ext_root).await? {
        total += le64(&body, 0)?;
    }
    Ok(total)
}

/// The block group `(start, len)` covering `addr`, from a `read_block_groups` list.
fn bg_of(bgs: &[(u64, u64, Vec<u8>)], addr: u64) -> Option<(u64, u64)> {
    bgs.iter()
        .find(|&&(s, l, _)| addr >= s && addr < s + l)
        .map(|&(s, l, _)| (s, l))
}

/// The extent-tree edits for a commit: a `METADATA_ITEM` per new/freed block, an
/// `EXTENT_ITEM` per new/freed data extent, and a `BLOCK_GROUP_ITEM` re-write for
/// each group whose `used` changed. All are keyed `Upsert`/`Delete`s the path-COW
/// engine can apply.
fn build_ext_edits(
    new_meta: &[(u64, u64, u8)],
    freed_meta: &[(u64, u8)],
    data: &DataChanges,
    bgs: &[(u64, u64, Vec<u8>)],
    gen: u64,
    nodesize: i64,
) -> Result<Vec<Edit>, FsError> {
    let mut edits = Vec::new();
    for &(addr, owner, lvl) in new_meta {
        edits.push(Edit::Upsert(
            BtrfsKey::new(addr, format::METADATA_ITEM_KEY, u64::from(lvl)),
            ext_item_meta(gen, owner),
        ));
    }
    for &(addr, lvl) in freed_meta {
        edits.push(Edit::Delete(BtrfsKey::new(
            addr,
            format::METADATA_ITEM_KEY,
            u64::from(lvl),
        )));
    }
    edits.extend(data.edits.iter().cloned());
    for (start, len, body) in bgs {
        let (s, e) = (*start, start + len);
        let mut net = 0i64;
        for &(a, _, _) in new_meta {
            if a >= s && a < e {
                net += nodesize;
            }
        }
        for &(a, _) in freed_meta {
            if a >= s && a < e {
                net -= nodesize;
            }
        }
        for &(b, l) in &data.allocated {
            if b >= s && b < e {
                net += l as i64;
            }
        }
        for &(b, l) in &data.released {
            if b >= s && b < e {
                net -= l as i64;
            }
        }
        if net != 0 {
            let mut nb = body.clone();
            let used = (le64(&nb, 0)? as i64 + net) as u64;
            nb[0..8].copy_from_slice(&used.to_le_bytes());
            edits.push(Edit::Upsert(
                BtrfsKey::new(*start, format::BLOCK_GROUP_ITEM_KEY, *len),
                nb,
            ));
        }
    }
    Ok(edits)
}

struct DataChanges {
    edits: Vec<Edit>,
    allocated: Vec<(u64, u64)>,
    released: Vec<(u64, u64)>,
}

/// Resolve one transaction's delayed data-reference adds/drops against the
/// current extent tree. The result separates logical ref edits from physical
/// allocation changes, which is what prevents a shared extent from being freed
/// while another snapshot still references it.
async fn resolve_data_changes<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    extent_root: u64,
    txn: &Txn,
    gen: u64,
) -> Result<DataChanges, FsError> {
    let mut bodies: BTreeMap<(u64, u64), Option<Vec<u8>>> = BTreeMap::new();
    let mut allocated = Vec::new();
    for data in &txn.new_data {
        let id = data.id;
        if bodies
            .insert(
                (id.bytenr, id.len),
                Some(ext_item_data(gen, id.ref_root, id.objectid, id.offset)),
            )
            .is_some()
        {
            return Err(FsError::InvalidData);
        }
        allocated.push((id.bytenr, id.len));
    }

    for (id, delta) in txn
        .added_data
        .iter()
        .map(|id| (id, 1i8))
        .chain(txn.dropped_data.iter().map(|id| (id, -1i8)))
    {
        let id = *id;
        let key = (id.bytenr, id.len);
        if let alloc::collections::btree_map::Entry::Vacant(entry) = bodies.entry(key) {
            let body = btree::find_item(
                vol,
                extent_root,
                &BtrfsKey::new(id.bytenr, format::EXTENT_ITEM_KEY, id.len),
            )
            .await?
            .ok_or(FsError::InvalidData)?;
            entry.insert(Some(body));
        }
        let current = bodies
            .get(&key)
            .and_then(Option::as_deref)
            .ok_or(FsError::InvalidData)?;
        let next = update_data_ref(current, &id, delta)?;
        bodies.insert(key, next);
    }

    let mut edits = Vec::with_capacity(bodies.len());
    let mut released = Vec::new();
    for ((bytenr, len), body) in bodies {
        let key = BtrfsKey::new(bytenr, format::EXTENT_ITEM_KEY, len);
        match body {
            Some(body) => edits.push(Edit::Upsert(key, body)),
            None => {
                edits.push(Edit::Delete(key));
                released.push((bytenr, len));
            }
        }
    }
    Ok(DataChanges {
        edits,
        allocated,
        released,
    })
}

/// Finalize a mutation. The fs tree arrives built (path-COW for the write path,
/// whole-repack for namespace ops); the **extent tree is path-COWed** — only the
/// leaves the block/data records touch are rewritten — while the csum, root and
/// free-space trees are still whole-repacked (they stay small).
///
/// The extent tree records its own new blocks, so how many blocks it (and the
/// other trees) produce depends on that record — a mutual recursion (btrfs's
/// delayed refs). `commit_txn` resolves it with a **fixed point**: it re-hands-out
/// every address from the same base each round (`Allocator::restore`), path-COWs
/// the extent tree and whole-repacks the rest, and repeats until the extent tree's
/// block set and the free-space leaf count stop changing. Only the converged
/// round is written. Fixed set of block groups (no chunk allocation here — the
/// caller grows and retries on `NoSpace`).
async fn commit_txn<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    gen: u64,
    mut alloc: Allocator,
    txn: Txn,
) -> Result<(), FsError> {
    let nodesize = vol.nodesize() as u64;
    let ns = vol.nodesize();
    let ss = u64::from(vol.sectorsize());
    let (root_tree, _) = vol.root_tree_root();

    let (old_ext, old_ext_level) =
        roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID).await?;
    let data_changes = resolve_data_changes(vol, old_ext, &txn, gen).await?;
    let touch_csum = !txn.new_data.is_empty() || !data_changes.released.is_empty();
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

    // Whole-repacked trees: read them as oversized logical leaves (+ old blocks).
    let (mut root_logical, root_old) = read_fs_oversized(vol, root_tree).await?;
    if let Some(flags) = txn.root_flags {
        let slot = leaf_find_by_type(&root_logical, vol.fs_tree_id(), format::ROOT_ITEM_KEY)?
            .ok_or(FsError::NotFound)?;
        let mut root_item = leaf_item_data(&root_logical, slot)?.to_vec();
        let end = roots::ROOT_ITEM_FLAGS + core::mem::size_of::<u64>();
        let field = root_item
            .get_mut(roots::ROOT_ITEM_FLAGS..end)
            .ok_or(FsError::InvalidData)?;
        field.copy_from_slice(&flags.to_le_bytes());
        leaf_replace_inplace(&mut root_logical, slot, &root_item)?;
    }
    for edit in &txn.root_edits {
        match edit {
            Edit::Upsert(key, body) => {
                if leaf_find(&root_logical, key)?.is_some() {
                    return Err(FsError::InvalidData);
                }
                leaf_insert_sorted(&mut root_logical, key, body)?;
            }
            Edit::Delete(key) => {
                let slot = leaf_find(&root_logical, key)?.ok_or(FsError::NotFound)?;
                leaf_delete(&mut root_logical, slot)?;
            }
        }
    }
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
    // Extent tree: read only its block groups (path COW touches its own leaves).
    let bgs = read_block_groups(vol, old_ext).await?;

    // csum tree: drop freed extents' csums, add new extents' csums.
    let csum_logical = match csum_logical {
        Some(mut cl) => {
            for &(bytenr, _) in &data_changes.released {
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
                    d.id.bytenr,
                );
                leaf_insert_sorted(&mut cl, &k, &d.csums)?;
            }
            Some(cl)
        }
        None => None,
    };

    // The fs tree arrives already path-COWed (nodes allocated from `alloc`).
    let c = &txn.fs;
    let mut fs_new_meta: Vec<(u64, u64, u8)> = c
        .new_blocks
        .iter()
        .map(|&(a, l)| (a, vol.fs_tree_id(), l))
        .collect();
    let (mut fs_nodes, mut fs_freed, fs_root_addr, fs_level) =
        (c.nodes.clone(), c.freed.clone(), c.root, c.level);
    let mut extra_roots = Vec::with_capacity(txn.extra_trees.len());
    for tree in &txn.extra_trees {
        fs_new_meta.extend(
            tree.commit
                .new_blocks
                .iter()
                .map(|&(a, l)| (a, tree.owner, l)),
        );
        fs_nodes.extend(tree.commit.nodes.clone());
        fs_freed.extend(tree.commit.freed.iter().copied());
        extra_roots.push((tree.owner, tree.commit.root, tree.commit.level));
    }
    fs_freed.extend(txn.retired_meta.iter().copied());

    let csum_groups = csum_logical
        .as_ref()
        .map(|c| group_items(vol, c))
        .transpose()?;
    let root_groups = group_items(vol, &root_logical)?;
    let csum_nc = csum_groups
        .as_ref()
        .map_or(0, |g| tree_block_count(g.len(), ns));
    let root_nc = tree_block_count(root_groups.len(), ns);
    let base = alloc.snapshot();

    // ── Mutual fixed point: whole-repack csum/root/fst, path-COW ext ────
    #[allow(clippy::type_complexity)]
    struct Done {
        csum_addrs: Vec<u64>,
        root_addrs: Vec<u64>,
        fst_addrs: Vec<u64>,
        fst_final: Option<Vec<u8>>,
        fst_groups: Option<Vec<(usize, usize)>>,
        csum_root: (u64, u8),
        fst_root: (u64, u8),
        ext_nodes: Vec<(u64, Vec<u8>, u8)>,
        ext_root: u64,
        ext_level: u8,
    }
    let mut done: Option<Done> = None;
    let mut prev_ext_new: Vec<(u64, u8)> = Vec::new();
    let mut prev_ext_freed: Vec<(u64, u8)> = Vec::new();
    let mut prev_ext_root = 0u64;
    let mut fst_leaves = usize::from(fst_base.is_some());

    for _ in 0..12 {
        alloc.restore(&base);
        let csum_addrs = alloc_nodes(&mut alloc, vol, csum_nc)?;
        let root_addrs = alloc_nodes(&mut alloc, vol, root_nc)?;
        let fst_addrs = alloc_nodes(
            &mut alloc,
            vol,
            if fst_leaves > 0 {
                tree_block_count(fst_leaves, ns)
            } else {
                0
            },
        )?;

        // Every new metadata block: fs (fixed) + this round's csum/root/fst +
        // last round's extent-tree blocks (the self-reference).
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
        if fst_leaves > 0 {
            collect_tree_meta(
                &fst_addrs,
                fst_leaves,
                ns,
                format::FREE_SPACE_TREE_OBJECTID,
                &mut new_meta,
            );
        }
        for &(a, l) in &prev_ext_new {
            new_meta.push((a, format::EXTENT_TREE_OBJECTID, l));
        }

        let mut freed_meta: Vec<(u64, u8)> = fs_freed.clone();
        freed_meta.extend(root_old.iter().copied());
        freed_meta.extend(csum_old.iter().copied());
        freed_meta.extend(fst_old.iter().copied());
        freed_meta.extend(prev_ext_freed.iter().copied());

        // Free-space tree: mark every new block used, return every freed block.
        let (fst_final, fst_groups) = match &fst_base {
            Some(fb) => {
                let mut ff = fb.clone();
                for &(a, _, _) in &new_meta {
                    let (s, l) = bg_of(&bgs, a).ok_or(FsError::InvalidData)?;
                    fst_mark_used(&mut ff, ss, s, l, a, nodesize)?;
                }
                for d in &txn.new_data {
                    let (s, l) = bg_of(&bgs, d.id.bytenr).ok_or(FsError::InvalidData)?;
                    fst_mark_used(&mut ff, ss, s, l, d.id.bytenr, d.id.len)?;
                }
                for &(a, _) in &freed_meta {
                    let (s, l) = bg_of(&bgs, a).ok_or(FsError::InvalidData)?;
                    fst_mark_free(&mut ff, ss, s, l, a, nodesize)?;
                }
                for &(b, l2) in &data_changes.released {
                    let (s, l) = bg_of(&bgs, b).ok_or(FsError::InvalidData)?;
                    fst_mark_free(&mut ff, ss, s, l, b, l2)?;
                }
                let g = group_items(vol, &ff)?;
                (Some(ff), Some(g))
            }
            None => (None, None),
        };
        let fst_root = fst_groups
            .as_ref()
            .map_or((0, 0), |g| tree_root_addr(&fst_addrs, g.len(), ns));

        // Path-COW the extent tree with this round's records.
        let ext_edits = build_ext_edits(
            &new_meta,
            &freed_meta,
            &data_changes,
            &bgs,
            gen,
            nodesize as i64,
        )?;
        let ext_out = PathCow::new(vol, gen, old_ext, old_ext_level)
            .await?
            .apply(&mut alloc, &ext_edits)
            .await?;

        let mut cur_ext_new: Vec<(u64, u8)> =
            ext_out.nodes.iter().map(|&(a, _, l)| (a, l)).collect();
        let mut cur_ext_freed = ext_out.freed.clone();
        cur_ext_new.sort_unstable();
        cur_ext_freed.sort_unstable();
        let fst_lv = fst_groups.as_ref().map_or(0, |g| g.len());

        let mut p_new = prev_ext_new.clone();
        let mut p_freed = prev_ext_freed.clone();
        p_new.sort_unstable();
        p_freed.sort_unstable();
        let converged = cur_ext_new == p_new
            && cur_ext_freed == p_freed
            && ext_out.root_addr == prev_ext_root
            && fst_lv == fst_leaves;
        if converged {
            let csum_root = csum_groups
                .as_ref()
                .map_or((0, 0), |g| tree_root_addr(&csum_addrs, g.len(), ns));
            done = Some(Done {
                csum_addrs,
                root_addrs,
                fst_addrs,
                fst_final,
                fst_groups,
                csum_root,
                fst_root,
                ext_nodes: ext_out.nodes,
                ext_root: ext_out.root_addr,
                ext_level: ext_out.root_level,
            });
            break;
        }
        prev_ext_new = cur_ext_new;
        prev_ext_freed = cur_ext_freed;
        prev_ext_root = ext_out.root_addr;
        fst_leaves = fst_lv;
    }
    let Done {
        csum_addrs,
        root_addrs,
        fst_addrs,
        fst_final,
        fst_groups,
        csum_root,
        fst_root,
        ext_nodes,
        ext_root,
        ext_level,
    } = done.ok_or(FsError::NoSpace)?;

    // ── Root tree: repoint each COWed tree's ROOT_ITEM, then pack it. ───
    let stamp_root_item = |ri: &mut [u8], bytenr: u64, tree_level: u8| {
        ri[160..168].copy_from_slice(&gen.to_le_bytes());
        ri[176..184].copy_from_slice(&bytenr.to_le_bytes());
        ri[238] = tree_level;
        if ri.len() >= 247 {
            ri[239..247].copy_from_slice(&gen.to_le_bytes());
        }
    };
    let fs_tree_changed = !c.nodes.is_empty() || !c.new_blocks.is_empty() || !c.freed.is_empty();
    let mut root_updates = alloc::vec![(format::EXTENT_TREE_OBJECTID, ext_root, ext_level)];
    if fs_tree_changed {
        root_updates.push((vol.fs_tree_id(), fs_root_addr, fs_level));
    }
    root_updates.extend(extra_roots);
    if csum_logical.is_some() {
        root_updates.push((format::CSUM_TREE_OBJECTID, csum_root.0, csum_root.1));
    }
    if fst_final.is_some() {
        root_updates.push((format::FREE_SPACE_TREE_OBJECTID, fst_root.0, fst_root.1));
    }
    for &(owner, new, lvl) in &root_updates {
        let slot = leaf_find_by_type(&root_logical, owner, format::ROOT_ITEM_KEY)?
            .ok_or(FsError::NotFound)?;
        let mut ri = leaf_item_data(&root_logical, slot)?.to_vec();
        stamp_root_item(&mut ri, new, lvl);
        leaf_replace_inplace(&mut root_logical, slot, &ri)?;
    }
    let (root_root_addr, _) = tree_root_addr(&root_addrs, root_groups.len(), ns);

    // ── Write every new node (extent-tree path-COW nodes are stamped here) ─
    let mut nodes: Vec<(u64, Vec<u8>)> = Vec::new();
    nodes.extend(fs_nodes);
    if let (Some(c), Some(g)) = (&csum_logical, &csum_groups) {
        nodes.extend(pack_tree_at(vol, c, g, &csum_addrs, gen)?.0);
    }
    for (addr, mut buf, _lvl) in ext_nodes {
        stamp_node(&mut buf, addr, gen, vol.csum_type())?;
        nodes.push((addr, buf));
    }
    nodes.extend(pack_tree_at(vol, &root_logical, &root_groups, &root_addrs, gen)?.0);
    if let (Some(f), Some(g)) = (&fst_final, &fst_groups) {
        nodes.extend(pack_tree_at(vol, f, g, &fst_addrs, gen)?.0);
    }
    for (addr, buf) in &nodes {
        if txn.root_flags.is_some() {
            vol.write_logical_root_admin(*addr, buf).await?;
        } else {
            vol.write_logical(*addr, buf).await?;
        }
    }

    // Superblock `bytes_used` is the sum of every block group's `used`, read back
    // from the freshly-written extent tree so it can never drift from the block
    // groups (`build_ext_edits` already committed each group's net).
    let bytes_used = total_block_group_used(vol, ext_root).await?;

    let mut raw = vol.read_raw_superblock().await?;
    raw[72..80].copy_from_slice(&gen.to_le_bytes());
    raw[80..88].copy_from_slice(&root_root_addr.to_le_bytes());
    raw[120..128].copy_from_slice(&bytes_used.to_le_bytes());
    crate::checksum::stamp_block(vol.csum_type(), &mut raw)?;
    vol.flush().await;
    if txn.root_flags.is_some() {
        vol.write_superblock_root_admin(&raw).await?;
    } else {
        vol.write_superblock(&raw).await?;
    }

    if let Some(f) = alloc.floor() {
        vol.set_alloc_floor(f);
    }
    vol.commit_roots(root_root_addr, fs_root_addr, fs_level, gen, txn.root_flags);
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
    dir_item_body_at(
        BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
        gen,
        ft,
        name,
    )
}

/// Build a directory item with an explicit location key. Ordinary entries
/// point at an `INODE_ITEM`; subvolume mount points point at a `ROOT_ITEM`.
fn dir_item_body_at(location: BtrfsKey, gen: u64, ft: u8, name: &[u8]) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 30 + name.len()];
    v[0..8].copy_from_slice(&location.objectid.to_le_bytes());
    v[8] = location.item_type;
    v[9..17].copy_from_slice(&location.offset.to_le_bytes());
    v[17..25].copy_from_slice(&gen.to_le_bytes()); // transid
                                                   // data_len@25 = 0
    v[27..29].copy_from_slice(&(name.len() as u16).to_le_bytes()); // name_len
    v[29] = ft; // type
    v[30..].copy_from_slice(name);
    v
}

/// Build a 53-byte regular extent item whose physical payload may be compressed.
/// `disk_len` is the sector-aligned stored length; `ram_len` is the logical
/// uncompressed range covered by the item.
fn file_extent_reg_encoded(
    gen: u64,
    disk_bytenr: u64,
    disk_len: u64,
    ram_len: u64,
    compression: u8,
) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 53];
    v[0..8].copy_from_slice(&gen.to_le_bytes()); // generation
    v[8..16].copy_from_slice(&ram_len.to_le_bytes()); // ram_bytes
    v[16] = compression;
    // encryption@17 / other_encoding@18 = 0
    v[20] = format::FILE_EXTENT_REG; // type
    v[21..29].copy_from_slice(&disk_bytenr.to_le_bytes()); // disk_bytenr
    v[29..37].copy_from_slice(&disk_len.to_le_bytes()); // disk_num_bytes
                                                        // extent_offset@37 = 0
    v[45..53].copy_from_slice(&ram_len.to_le_bytes()); // num_bytes
    v
}

/// Next free inode number: one past the highest in-range `INODE_ITEM` objectid.
async fn next_inode_number<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
) -> Result<u64, FsError> {
    // The greatest key below the inode-number ceiling belongs to the highest-
    // numbered inode (every inode owns at least an INODE_ITEM at its objectid).
    let ceiling = BtrfsKey::new(format::LAST_FREE_OBJECTID + 1, 0, 0);
    let max = match btree::last_before(vol, fs_root, &ceiling).await? {
        Some((k, _))
            if k.objectid >= format::FIRST_FREE_OBJECTID
                && k.objectid <= format::LAST_FREE_OBJECTID =>
        {
            k.objectid
        }
        _ => format::FIRST_FREE_OBJECTID,
    };
    Ok(max + 1)
}

/// Next `DIR_INDEX` sequence for directory `dir_ino`: one past the highest
/// existing index (indices 0/1 are reserved for `.`/`..`, so the first real
/// entry is 2).
async fn next_dir_index<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    dir_ino: u64,
) -> Result<u64, FsError> {
    let ceiling = BtrfsKey::new(dir_ino, format::DIR_INDEX_KEY + 1, 0);
    let max = match btree::last_before(vol, fs_root, &ceiling).await? {
        Some((k, _)) if k.objectid == dir_ino && k.item_type == format::DIR_INDEX_KEY => k.offset,
        _ => 1,
    };
    Ok(max + 1)
}

/// Allocate the next ordinary subvolume/tree objectid from the root tree.
async fn next_subvol_id<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root_tree: u64,
) -> Result<u64, FsError> {
    let mut cursor = btree::Cursor::seek(
        vol,
        root_tree,
        &BtrfsKey::new(format::FIRST_FREE_OBJECTID, 0, 0),
    )
    .await?;
    let mut max_id = format::FIRST_FREE_OBJECTID - 1;
    while let Some((key, _)) = cursor.current()? {
        if key.objectid > format::LAST_FREE_OBJECTID {
            break;
        }
        if key.item_type == format::ROOT_ITEM_KEY {
            max_id = max_id.max(key.objectid);
        }
        cursor.advance().await?;
    }
    let next = max_id.checked_add(1).ok_or(FsError::NoSpace)?;
    if next > format::LAST_FREE_OBJECTID {
        return Err(FsError::NoSpace);
    }
    Ok(next)
}

/// `struct btrfs_root_ref` followed by its name.
fn root_ref(dirid: u64, sequence: u64, name: &[u8]) -> Vec<u8> {
    let mut body = alloc::vec![0u8; 18 + name.len()];
    body[0..8].copy_from_slice(&dirid.to_le_bytes());
    body[8..16].copy_from_slice(&sequence.to_le_bytes());
    body[16..18].copy_from_slice(&(name.len() as u16).to_le_bytes());
    body[18..].copy_from_slice(name);
    body
}

/// Derive a stable, filesystem-local RFC-4122-shaped UUID for a new subvolume.
/// The current filesystem UUID, generation and never-reused tree id make the
/// seed unique for this volume; SHA-256 provides a full-width deterministic
/// digest without depending on a userspace RNG during an ioctl transaction.
fn subvol_uuid(fsid: &[u8], gen: u64, tree_id: u64) -> Result<[u8; 16], FsError> {
    let mut seed = Vec::with_capacity(fsid.len() + 16);
    seed.extend_from_slice(fsid);
    seed.extend_from_slice(&gen.to_le_bytes());
    seed.extend_from_slice(&tree_id.to_le_bytes());
    let digest = crate::checksum::digest(format::CSUM_TYPE_SHA256, &seed)?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    Ok(uuid)
}

/// Build the modern 439-byte `btrfs_root_item` for a new empty subvolume.
#[allow(clippy::too_many_arguments)]
fn subvol_root_item(
    gen: u64,
    bytenr: u64,
    nodesize: u64,
    flags: u64,
    uuid: &[u8; 16],
    time_sec: i64,
    time_nsec: u32,
) -> Vec<u8> {
    let mut item = alloc::vec![0u8; 439];
    let embedded = inode_item(gen, 0o040755, 0, 0, 1, 0, 0, 0, time_sec, time_nsec);
    item[..160].copy_from_slice(&embedded);
    item[160..168].copy_from_slice(&gen.to_le_bytes()); // generation
    item[168..176].copy_from_slice(&format::FIRST_FREE_OBJECTID.to_le_bytes()); // root_dirid
    item[176..184].copy_from_slice(&bytenr.to_le_bytes());
    item[192..200].copy_from_slice(&nodesize.to_le_bytes()); // bytes_used
    item[208..216].copy_from_slice(&flags.to_le_bytes());
    item[216..220].copy_from_slice(&1u32.to_le_bytes()); // refs
    item[238] = 0; // level (the new tree is one leaf)
    item[239..247].copy_from_slice(&gen.to_le_bytes()); // generation_v2
    item[247..263].copy_from_slice(uuid);
    item[295..303].copy_from_slice(&gen.to_le_bytes()); // ctransid
    item[303..311].copy_from_slice(&gen.to_le_bytes()); // otransid
    for off in [327usize, 339] {
        item[off..off + 8].copy_from_slice(&(time_sec as u64).to_le_bytes());
        item[off + 8..off + 12].copy_from_slice(&time_nsec.to_le_bytes());
    }
    item
}

/// Create an empty subvolume below `parent_ino`, atomically COWing the parent
/// tree, new child tree, UUID tree, root tree and extent/free-space metadata.
/// Returns the new subvolume's tree objectid.
pub(crate) async fn create_subvolume<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    name: &str,
    readonly: bool,
) -> Result<u64, FsError> {
    let name_bytes = name.as_bytes();
    if name.is_empty() || name_bytes.len() > 255 || name.contains('/') {
        return Err(FsError::InvalidData);
    }
    let (fs_root, fs_level) = vol.fs_tree_root();
    let (root_tree, _) = vol.root_tree_root();
    let dir_item_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );
    let existing_dir_item = btree::find_item(vol, fs_root, &dir_item_key).await?;
    if existing_dir_item
        .as_deref()
        .is_some_and(|body| find_dir_item(body, name).is_ok())
    {
        return Err(FsError::InvalidData);
    }

    let gen = vol
        .superblock()
        .generation
        .checked_add(1)
        .ok_or(FsError::InvalidData)?;
    let new_id = next_subvol_id(vol, root_tree).await?;
    let new_index = next_dir_index(vol, fs_root, parent_ino).await?;
    let mut alloc = Allocator::build(vol).await?;

    let mut pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    let psize = le64(&pinode, 16)?;
    let ptime_sec = le64(&pinode, 136)? as i64;
    let ptime_nsec = format::le32(&pinode, 144)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes());
    pinode[16..24].copy_from_slice(&(psize + 2 * name_bytes.len() as u64).to_le_bytes());
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes());

    let location = BtrfsKey::new(new_id, format::ROOT_ITEM_KEY, 0);
    let di = dir_item_body_at(location, gen, format::FT_DIR, name_bytes);
    let parent_edits = alloc::vec![
        Edit::Upsert(BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0), pinode),
        Edit::Upsert(
            dir_item_key,
            append_dir_item(existing_dir_item.as_deref(), name, &di)?,
        ),
        Edit::Upsert(
            BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, new_index),
            di,
        ),
    ];
    let parent_out = PathCow::new(vol, gen, fs_root, fs_level)
        .await?
        .apply(&mut alloc, &parent_edits)
        .await?;
    let parent_commit = fs_commit_from(parent_out, gen, vol.csum_type())?;

    // The new fs tree starts as a single leaf containing its root inode and `..`.
    let child_addr = alloc.alloc_node(vol)?;
    let header = vol.read_node(fs_root).await?;
    let child_inode = inode_item(gen, 0o040755, 0, 0, 1, 0, 0, 0, ptime_sec, ptime_nsec);
    let child_parent = inode_ref(0, b"..");
    let child_items = [
        (
            BtrfsKey::new(format::FIRST_FREE_OBJECTID, format::INODE_ITEM_KEY, 0),
            child_inode.as_slice(),
        ),
        (
            BtrfsKey::new(
                format::FIRST_FREE_OBJECTID,
                format::INODE_REF_KEY,
                format::FIRST_FREE_OBJECTID,
            ),
            child_parent.as_slice(),
        ),
    ];
    let mut child_node = pack_leaf(&header, &child_items, vol.nodesize());
    child_node[HDR_OWNER..HDR_OWNER + 8].copy_from_slice(&new_id.to_le_bytes());
    stamp_node(&mut child_node, child_addr, gen, vol.csum_type())?;

    let raw_super = vol.read_raw_superblock().await?;
    let fsid = raw_super.get(32..48).ok_or(FsError::InvalidData)?;
    let uuid = subvol_uuid(fsid, gen, new_id)?;
    let flags = if readonly {
        format::ROOT_SUBVOL_RDONLY
    } else {
        0
    };
    let root_item = subvol_root_item(
        gen,
        child_addr,
        vol.nodesize() as u64,
        flags,
        &uuid,
        ptime_sec,
        ptime_nsec,
    );
    let ref_body = root_ref(parent_ino, new_index, name_bytes);
    let root_edits = alloc::vec![
        Edit::Upsert(BtrfsKey::new(new_id, format::ROOT_ITEM_KEY, 0), root_item),
        Edit::Upsert(
            BtrfsKey::new(new_id, format::ROOT_BACKREF_KEY, vol.fs_tree_id()),
            ref_body.clone(),
        ),
        Edit::Upsert(
            BtrfsKey::new(vol.fs_tree_id(), format::ROOT_REF_KEY, new_id),
            ref_body,
        ),
    ];

    let mut extra_trees = alloc::vec![ExtraTree {
        owner: new_id,
        commit: FsCommit {
            nodes: alloc::vec![(child_addr, child_node)],
            new_blocks: alloc::vec![(child_addr, 0)],
            freed: Vec::new(),
            root: child_addr,
            level: 0,
        },
    }];

    // Modern filesystems index every subvolume UUID. Older images without a
    // UUID tree remain supported; their root item still carries the UUID.
    if let Ok((uuid_root, uuid_level)) =
        roots::find_root(vol, root_tree, format::UUID_TREE_OBJECTID).await
    {
        let uuid_key = BtrfsKey::new(
            u64::from_le_bytes(uuid[..8].try_into().unwrap()),
            format::UUID_KEY_SUBVOL,
            u64::from_le_bytes(uuid[8..].try_into().unwrap()),
        );
        let uuid_out = PathCow::new(vol, gen, uuid_root, uuid_level)
            .await?
            .apply(
                &mut alloc,
                &[Edit::Upsert(uuid_key, new_id.to_le_bytes().to_vec())],
            )
            .await?;
        extra_trees.push(ExtraTree {
            owner: format::UUID_TREE_OBJECTID,
            commit: fs_commit_from(uuid_out, gen, vol.csum_type())?,
        });
    }

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: parent_commit,
            dropped_data: Vec::new(),
            added_data: Vec::new(),
            new_data: Vec::new(),
            root_flags: None,
            extra_trees,
            root_edits,
            retired_meta: Vec::new(),
        },
    )
    .await?;
    Ok(new_id)
}

/// Create a point-in-time subvolume snapshot below the parent inode.
///
/// Metadata is rebuilt under the new root owner while regular data extents are
/// shared by adding ordinary `EXTENT_DATA_REF`s. This avoids copying file data,
/// and delayed drops keep source/snapshot writes and deletion independent.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_snapshot<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    source_root: u64,
    source_id: u64,
    name: &str,
    readonly: bool,
) -> Result<u64, FsError> {
    let name_bytes = name.as_bytes();
    if name.is_empty() || name_bytes.len() > 255 || name.contains('/') {
        return Err(FsError::InvalidData);
    }
    let (fs_root, fs_level) = vol.fs_tree_root();
    let (root_tree, _) = vol.root_tree_root();
    let dir_item_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );
    let existing_dir_item = btree::find_item(vol, fs_root, &dir_item_key).await?;
    if existing_dir_item
        .as_deref()
        .is_some_and(|body| find_dir_item(body, name).is_ok())
    {
        return Err(FsError::InvalidData);
    }

    let gen = vol
        .superblock()
        .generation
        .checked_add(1)
        .ok_or(FsError::InvalidData)?;
    let new_id = next_subvol_id(vol, root_tree).await?;
    let new_index = next_dir_index(vol, fs_root, parent_ino).await?;
    let mut alloc = Allocator::build(vol).await?;

    let (mut child_logical, _) = read_fs_oversized(vol, source_root).await?;
    let item_count = nritems(&child_logical)? as usize;
    for slot in 0..item_count {
        let key = leaf_item_key(&child_logical, slot)?;
        if key.item_type == format::DIR_INDEX_KEY {
            for entry in decode_dir_items(leaf_item_data(&child_logical, slot)?)? {
                if entry.location.item_type == format::ROOT_ITEM_KEY {
                    return Err(FsError::Unsupported);
                }
            }
        }
    }

    let sectorsize = u64::from(vol.sectorsize());
    let mut added_data = Vec::new();
    for slot in 0..item_count {
        let key = leaf_item_key(&child_logical, slot)?;
        if key.item_type != format::EXTENT_DATA_KEY {
            continue;
        }
        let body = leaf_item_data(&child_logical, slot)?;
        if body.len() < 21 {
            return Err(FsError::InvalidData);
        }
        if body[20] == format::FILE_EXTENT_INLINE {
            continue;
        }
        if !matches!(
            body[20],
            format::FILE_EXTENT_REG | format::FILE_EXTENT_PREALLOC
        ) || body.len() < 53
        {
            return Err(FsError::InvalidData);
        }
        let old_bytenr = le64(body, 21)?;
        if old_bytenr == 0 {
            continue;
        }
        let disk_len = le64(body, 29)?;
        if disk_len == 0 || disk_len % sectorsize != 0 {
            return Err(FsError::InvalidData);
        }
        let extent_offset = le64(body, 37)?;
        let backref_offset = key
            .offset
            .checked_sub(extent_offset)
            .ok_or(FsError::InvalidData)?;
        added_data.push(DataRefId {
            bytenr: old_bytenr,
            len: disk_len,
            ref_root: new_id,
            objectid: key.objectid,
            offset: backref_offset,
        });
    }

    child_logical[HDR_OWNER..HDR_OWNER + 8].copy_from_slice(&new_id.to_le_bytes());
    let child_groups = group_items(vol, &child_logical)?;
    let child_addrs = alloc_nodes(
        &mut alloc,
        vol,
        tree_block_count(child_groups.len(), vol.nodesize()),
    )?;
    let (child_nodes, child_root, child_level) =
        pack_tree_at(vol, &child_logical, &child_groups, &child_addrs, gen)?;
    let mut child_blocks = Vec::new();
    collect_tree_meta(
        &child_addrs,
        child_groups.len(),
        vol.nodesize(),
        new_id,
        &mut child_blocks,
    );

    let mut pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    let psize = le64(&pinode, 16)?;
    let ptime_sec = le64(&pinode, 136)? as i64;
    let ptime_nsec = format::le32(&pinode, 144)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes());
    pinode[16..24].copy_from_slice(&(psize + 2 * name_bytes.len() as u64).to_le_bytes());
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes());

    let location = BtrfsKey::new(new_id, format::ROOT_ITEM_KEY, 0);
    let di = dir_item_body_at(location, gen, format::FT_DIR, name_bytes);
    let parent_edits = alloc::vec![
        Edit::Upsert(BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0), pinode),
        Edit::Upsert(
            dir_item_key,
            append_dir_item(existing_dir_item.as_deref(), name, &di)?,
        ),
        Edit::Upsert(
            BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, new_index),
            di,
        ),
    ];
    let parent_out = PathCow::new(vol, gen, fs_root, fs_level)
        .await?
        .apply(&mut alloc, &parent_edits)
        .await?;
    let parent_commit = fs_commit_from(parent_out, gen, vol.csum_type())?;

    let source_key = BtrfsKey::new(source_id, format::ROOT_ITEM_KEY, 0);
    let source_cursor = btree::Cursor::seek(vol, root_tree, &source_key).await?;
    let source_item = match source_cursor.current()? {
        Some((key, body))
            if key.objectid == source_id && key.item_type == format::ROOT_ITEM_KEY =>
        {
            body.to_vec()
        }
        _ => return Err(FsError::NotFound),
    };
    let raw_super = vol.read_raw_superblock().await?;
    let fsid = raw_super.get(32..48).ok_or(FsError::InvalidData)?;
    let uuid = subvol_uuid(fsid, gen, new_id)?;
    let flags = if readonly {
        format::ROOT_SUBVOL_RDONLY
    } else {
        0
    };
    let tree_bytes = (child_blocks.len() as u64)
        .checked_mul(vol.nodesize() as u64)
        .ok_or(FsError::InvalidData)?;
    let mut root_item = subvol_root_item(
        gen, child_root, tree_bytes, flags, &uuid, ptime_sec, ptime_nsec,
    );
    root_item[238] = child_level;
    if let Some(root_inode) = (0..item_count).find_map(|slot| {
        let key = leaf_item_key(&child_logical, slot).ok()?;
        if key == BtrfsKey::new(format::FIRST_FREE_OBJECTID, format::INODE_ITEM_KEY, 0) {
            Some(leaf_item_data(&child_logical, slot).ok()?.to_vec())
        } else {
            None
        }
    }) {
        if root_inode.len() >= 160 {
            root_item[..160].copy_from_slice(&root_inode[..160]);
        }
    }
    if let Some(parent_uuid) = source_item.get(247..263) {
        root_item[263..279].copy_from_slice(parent_uuid);
    }
    let ref_body = root_ref(parent_ino, new_index, name_bytes);
    let root_edits = alloc::vec![
        Edit::Upsert(BtrfsKey::new(new_id, format::ROOT_ITEM_KEY, 0), root_item),
        Edit::Upsert(
            BtrfsKey::new(new_id, format::ROOT_BACKREF_KEY, vol.fs_tree_id()),
            ref_body.clone(),
        ),
        Edit::Upsert(
            BtrfsKey::new(vol.fs_tree_id(), format::ROOT_REF_KEY, new_id),
            ref_body,
        ),
    ];

    let mut extra_trees = alloc::vec![ExtraTree {
        owner: new_id,
        commit: FsCommit {
            nodes: child_nodes,
            new_blocks: child_blocks
                .into_iter()
                .map(|(addr, _owner, level)| (addr, level))
                .collect(),
            freed: Vec::new(),
            root: child_root,
            level: child_level,
        },
    }];
    if let Ok((uuid_root, uuid_level)) =
        roots::find_root(vol, root_tree, format::UUID_TREE_OBJECTID).await
    {
        let uuid_key = BtrfsKey::new(
            u64::from_le_bytes(uuid[..8].try_into().unwrap()),
            format::UUID_KEY_SUBVOL,
            u64::from_le_bytes(uuid[8..].try_into().unwrap()),
        );
        let uuid_out = PathCow::new(vol, gen, uuid_root, uuid_level)
            .await?
            .apply(
                &mut alloc,
                &[Edit::Upsert(uuid_key, new_id.to_le_bytes().to_vec())],
            )
            .await?;
        extra_trees.push(ExtraTree {
            owner: format::UUID_TREE_OBJECTID,
            commit: fs_commit_from(uuid_out, gen, vol.csum_type())?,
        });
    }

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: parent_commit,
            dropped_data: Vec::new(),
            added_data,
            new_data: Vec::new(),
            root_flags: None,
            extra_trees,
            root_edits,
            retired_meta: Vec::new(),
        },
    )
    .await?;
    Ok(new_id)
}

async fn require_exclusive_extent<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    extent_root: u64,
    key: BtrfsKey,
    inline_ref_type: u8,
    ref_root: u64,
    objectid: u64,
    offset: u64,
) -> Result<(), FsError> {
    let body = btree::find_item(vol, extent_root, &key)
        .await?
        .ok_or(FsError::InvalidData)?;
    if body.len() < 33 || le64(&body, 0)? != 1 || body[24] != inline_ref_type {
        return Err(FsError::Unsupported);
    }
    if le64(&body, 25)? != ref_root {
        return Err(FsError::Unsupported);
    }
    if inline_ref_type == EXTENT_DATA_REF_KEY
        && (body.len() < 53
            || le64(&body, 33)? != objectid
            || le64(&body, 41)? != offset
            || format::le32(&body, 49)? != 1)
    {
        return Err(FsError::Unsupported);
    }
    Ok(())
}

/// Delete a direct child subvolume by name or id and reclaim its exclusive tree.
///
/// Shared metadata/data extents are rejected before the transaction starts.
/// This makes deletion safe for ordinary subvolumes and NARF's isolated
/// snapshots without pretending that shared delayed refs are implemented.
pub(crate) async fn destroy_subvolume<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    parent_ino: u64,
    requested_name: Option<&str>,
    requested_id: Option<u64>,
) -> Result<(), FsError> {
    if requested_name.is_some() == requested_id.is_some() {
        return Err(FsError::InvalidData);
    }
    if requested_name.is_some_and(|name| name.is_empty() || name.len() > 255 || name.contains('/'))
    {
        return Err(FsError::InvalidData);
    }
    let (fs_root, fs_level) = vol.fs_tree_root();
    let (root_tree, _) = vol.root_tree_root();

    // DIR_INDEX is the authoritative parent/name/index relation and also lets
    // the V2 by-id form recover the name needed to remove the DIR_ITEM bucket.
    let mut found: Option<(String, u64, u64)> = None;
    for (key, body) in btree::collect_for(vol, fs_root, parent_ino, format::DIR_INDEX_KEY).await? {
        for entry in decode_dir_items(&body)? {
            if entry.location.item_type != format::ROOT_ITEM_KEY {
                continue;
            }
            let name_match = requested_name.is_some_and(|name| entry.name == name);
            let id_match = requested_id.is_some_and(|id| entry.location.objectid == id);
            if name_match || id_match {
                if found.is_some() {
                    return Err(FsError::InvalidData);
                }
                found = Some((entry.name, entry.location.objectid, key.offset));
            }
        }
    }
    let (name, child_id, dir_index) = found.ok_or(FsError::NotFound)?;
    if child_id == vol.fs_tree_id() {
        return Err(FsError::Busy);
    }
    let name_bytes = name.as_bytes();
    let dir_item_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );
    let dir_item = btree::find_item(vol, fs_root, &dir_item_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let entry = find_dir_item(&dir_item, &name)?;
    if entry.location.item_type != format::ROOT_ITEM_KEY || entry.location.objectid != child_id {
        return Err(FsError::InvalidData);
    }
    let dir_remaining = remove_dir_item(&dir_item, &name)?;

    let root_start = BtrfsKey::new(child_id, format::ROOT_ITEM_KEY, 0);
    let root_cursor = btree::Cursor::seek(vol, root_tree, &root_start).await?;
    let (root_item_key, root_item) = match root_cursor.current()? {
        Some((key, body)) if key.objectid == child_id && key.item_type == format::ROOT_ITEM_KEY => {
            (key, body.to_vec())
        }
        _ => return Err(FsError::NotFound),
    };
    let (child_root, _child_level) = roots::find_root(vol, root_tree, child_id).await?;
    let (child_logical, child_blocks) = read_fs_oversized(vol, child_root).await?;

    // A nested subvolume is a separate root and must survive deletion of its
    // parent; implementing the orphan/stub semantics is deferred.
    let child_items = nritems(&child_logical)? as usize;
    for slot in 0..child_items {
        let key = leaf_item_key(&child_logical, slot)?;
        if key.item_type == format::DIR_INDEX_KEY {
            for entry in decode_dir_items(leaf_item_data(&child_logical, slot)?)? {
                if entry.location.item_type == format::ROOT_ITEM_KEY {
                    return Err(FsError::Unsupported);
                }
            }
        }
    }

    let (extent_root, _) = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID).await?;
    for &(addr, level) in &child_blocks {
        require_exclusive_extent(
            vol,
            extent_root,
            BtrfsKey::new(addr, format::METADATA_ITEM_KEY, u64::from(level)),
            TREE_BLOCK_REF_KEY,
            child_id,
            0,
            0,
        )
        .await?;
    }

    let mut dropped_data = Vec::new();
    for slot in 0..child_items {
        let key = leaf_item_key(&child_logical, slot)?;
        if key.item_type != format::EXTENT_DATA_KEY {
            continue;
        }
        let body = leaf_item_data(&child_logical, slot)?;
        if body.len() < 21 || body[20] == format::FILE_EXTENT_INLINE {
            continue;
        }
        if body.len() < 53
            || !matches!(
                body[20],
                format::FILE_EXTENT_REG | format::FILE_EXTENT_PREALLOC
            )
        {
            return Err(FsError::InvalidData);
        }
        let bytenr = le64(body, 21)?;
        if bytenr == 0 {
            continue;
        }
        let len = le64(body, 29)?;
        let extent_offset = le64(body, 37)?;
        let backref_offset = key
            .offset
            .checked_sub(extent_offset)
            .ok_or(FsError::InvalidData)?;
        dropped_data.push(DataRefId {
            bytenr,
            len,
            ref_root: child_id,
            objectid: key.objectid,
            offset: backref_offset,
        });
    }

    let gen = vol
        .superblock()
        .generation
        .checked_add(1)
        .ok_or(FsError::InvalidData)?;
    let mut alloc = Allocator::build(vol).await?;
    let mut pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    let psize = le64(&pinode, 16)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes());
    pinode[16..24].copy_from_slice(
        &psize
            .saturating_sub(2 * name_bytes.len() as u64)
            .to_le_bytes(),
    );
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes());
    let parent_edits = alloc::vec![
        Edit::Upsert(BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0), pinode),
        if dir_remaining.is_empty() {
            Edit::Delete(dir_item_key)
        } else {
            Edit::Upsert(dir_item_key, dir_remaining)
        },
        Edit::Delete(BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, dir_index,)),
    ];
    let parent_out = PathCow::new(vol, gen, fs_root, fs_level)
        .await?
        .apply(&mut alloc, &parent_edits)
        .await?;
    let parent_commit = fs_commit_from(parent_out, gen, vol.csum_type())?;

    let parent_id = vol.fs_tree_id();
    let root_edits = alloc::vec![
        Edit::Delete(root_item_key),
        Edit::Delete(BtrfsKey::new(child_id, format::ROOT_BACKREF_KEY, parent_id,)),
        Edit::Delete(BtrfsKey::new(parent_id, format::ROOT_REF_KEY, child_id,)),
    ];
    // Validate the relationship before the root-tree delete turns it into a
    // hard transaction error halfway through construction.
    for key in root_edits.iter().filter_map(|edit| match edit {
        Edit::Delete(key) => Some(key),
        Edit::Upsert(_, _) => None,
    }) {
        if btree::find_item(vol, root_tree, key).await?.is_none() {
            return Err(FsError::InvalidData);
        }
    }

    let mut extra_trees = Vec::new();
    if let (Some(uuid), Ok((uuid_root, uuid_level))) = (
        root_item.get(247..263),
        roots::find_root(vol, root_tree, format::UUID_TREE_OBJECTID).await,
    ) {
        let uuid_key = BtrfsKey::new(
            u64::from_le_bytes(uuid[..8].try_into().unwrap()),
            format::UUID_KEY_SUBVOL,
            u64::from_le_bytes(uuid[8..].try_into().unwrap()),
        );
        if btree::find_item(vol, uuid_root, &uuid_key).await?.is_none() {
            return Err(FsError::InvalidData);
        }
        let uuid_out = PathCow::new(vol, gen, uuid_root, uuid_level)
            .await?
            .apply(&mut alloc, &[Edit::Delete(uuid_key)])
            .await?;
        extra_trees.push(ExtraTree {
            owner: format::UUID_TREE_OBJECTID,
            commit: fs_commit_from(uuid_out, gen, vol.csum_type())?,
        });
    }

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: parent_commit,
            dropped_data,
            added_data: Vec::new(),
            new_data: Vec::new(),
            root_flags: None,
            extra_trees,
            root_edits,
            retired_meta: child_blocks,
        },
    )
    .await
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
/// `parent_ino` (mounted subvolume). `mode` carries the `S_IF*` type bits; `rdev`
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

/// Create a new inode named `name` in directory `parent_ino` (mounted subvolume)
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

    let (fs_root, _) = vol.fs_tree_root();

    // A different name with the same hash shares this DIR_ITEM body. The VFS
    // pre-checks exact duplicates; keep a defensive check here as well.
    let dir_item_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );
    let existing_dir_item = btree::find_item(vol, fs_root, &dir_item_key).await?;
    if existing_dir_item
        .as_deref()
        .is_some_and(|body| find_dir_item(body, name).is_ok())
    {
        return Err(FsError::InvalidData);
    }

    let new_ino = next_inode_number(vol, fs_root).await?;
    let new_index = next_dir_index(vol, fs_root, parent_ino).await?;
    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    // Update the parent dir inode: btrfs directory `i_size` is the sum of entry
    // name lengths, so grow it by this name; bump transid + sequence. Borrow the
    // parent's mtime for the new inode's timestamps (no wall clock here).
    let mut pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    let psize = le64(&pinode, 16)?;
    let ptime_sec = le64(&pinode, 136)? as i64;
    let ptime_nsec = format::le32(&pinode, 144)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
                                                       // btrfs directory `i_size` counts each entry's name twice (DIR_ITEM +
                                                       // DIR_INDEX) — see `btrfs_add_link` (`i_size + name->len * 2`).
    pinode[16..24].copy_from_slice(&(psize + 2 * name_bytes.len() as u64).to_le_bytes());
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes()); // sequence

    // Insert the new inode's items: INODE_ITEM, INODE_REF (→ parent), and the
    // parent's DIR_ITEM (name lookup) + DIR_INDEX (readdir order). Inline content
    // (a symlink target) sets the inode size/nbytes and adds an EXTENT_DATA.
    // An inline symlink's data lives in the item, so `nbytes` equals `size`;
    // empty files/dirs/device nodes own no bytes.
    let size = spec.inline.map(|d| d.len() as u64).unwrap_or(0);
    let ii = inode_item(
        gen, spec.mode, size, size, 1, 0, 0, spec.rdev, ptime_sec, ptime_nsec,
    );
    let di = dir_item_body(new_ino, gen, spec.ftype, name_bytes);
    let di_bucket = append_dir_item(existing_dir_item.as_deref(), name, &di)?;
    let mut edits = alloc::vec![
        Edit::Upsert(BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0), pinode),
        Edit::Upsert(BtrfsKey::new(new_ino, format::INODE_ITEM_KEY, 0), ii),
        Edit::Upsert(
            BtrfsKey::new(new_ino, format::INODE_REF_KEY, parent_ino),
            inode_ref(new_index, name_bytes),
        ),
        Edit::Upsert(dir_item_key, di_bucket),
        Edit::Upsert(
            BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, new_index),
            di,
        ),
    ];
    if let Some(data) = spec.inline {
        edits.push(Edit::Upsert(
            BtrfsKey::new(new_ino, format::EXTENT_DATA_KEY, 0),
            file_extent_inline(gen, data),
        ));
    }

    commit_fs_edits(vol, gen, alloc, &edits, Vec::new(), Vec::new()).await?;

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

/// Remove the entry `name` from directory `parent_ino` (mounted subvolume) via a
/// COW mini-transaction. On the inode's **last** link the inode is freed (its
/// `INODE_ITEM` + `EXTENT_DATA` removed, its regular data extents + checksums
/// released); a still-linked inode keeps its data and just loses this name and one
/// `INODE_REF` entry, its `nlink` decremented.
///
/// Directories (use `rmdir`) and subvolume mount points remain out of scope;
/// hash-colliding peer names in the same `DIR_ITEM` are preserved.
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

    // Resolve the exact name inside its possibly colliding hash bucket.
    let dir_item_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );
    let di_body = btree::find_item(vol, fs_root, &dir_item_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let entry = find_dir_item(&di_body, name)?;
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported); // subvolume mount point
    }
    if entry.ftype == format::FT_DIR {
        return Err(FsError::InvalidData); // a directory: use rmdir
    }
    let child_ino = entry.location.objectid;
    let di_remaining = remove_dir_item(&di_body, name)?;

    // Load the child inode; directories use rmdir.
    let ci_body = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    let cinode = InodeItem::decode(&ci_body)?;
    if cinode.is_dir() {
        return Err(FsError::InvalidData);
    }
    let last_link = cinode.nlink <= 1;

    // Locate this name's INODE_REF entry: its DIR_INDEX offset + the entries that
    // survive removing it (empty when it was the inode's only ref in this dir).
    let ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, parent_ino);
    let ref_body = btree::find_item(vol, fs_root, &ref_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let (dir_index, ref_remaining) = inode_ref_remove(&ref_body, name_bytes)?;

    // On the last link, gather the inode's regular data extents (to free) and its
    // EXTENT_DATA keys (to delete). A still-linked inode keeps its data; inline
    // extents and holes own no separate disk block.
    let mut dropped_data = Vec::new();
    let mut ed_offsets: Vec<u64> = Vec::new();
    let mut xattr_keys: Vec<BtrfsKey> = Vec::new();
    if last_link {
        for (k, body) in
            btree::collect_for(vol, fs_root, child_ino, format::EXTENT_DATA_KEY).await?
        {
            ed_offsets.push(k.offset);
            // type@20; disk_bytenr@21; disk_num_bytes@29.
            if body.len() >= 53 && body[20] != format::FILE_EXTENT_INLINE {
                let disk_bytenr = le64(&body, 21)?;
                let disk_num = le64(&body, 29)?;
                if disk_bytenr != 0 {
                    dropped_data.push(DataRefId {
                        bytenr: disk_bytenr,
                        len: disk_num,
                        ref_root: vol.fs_tree_id(),
                        objectid: child_ino,
                        offset: k
                            .offset
                            .checked_sub(le64(&body, 37)?)
                            .ok_or(FsError::InvalidData)?,
                    });
                }
            }
        }
        xattr_keys = btree::collect_for(vol, fs_root, child_ino, format::XATTR_ITEM_KEY)
            .await?
            .into_iter()
            .map(|(key, _)| key)
            .collect();
    }

    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    let mut edits = Vec::new();

    // A surviving inode keeps its INODE_ITEM with `nlink` decremented.
    if !last_link {
        let mut ci = ci_body;
        ci[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
        ci[40..44].copy_from_slice(&(cinode.nlink - 1).to_le_bytes());
        edits.push(Edit::Upsert(
            BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
            ci,
        ));
    }

    // Shrink the parent dir inode by this entry's name length; bump transid+seq.
    let mut pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
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
    edits.push(Edit::Upsert(
        BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
        pinode,
    ));

    // Delete this name's DIR_ITEM + DIR_INDEX; on the last link also the
    // INODE_ITEM + EXTENT_DATA. The INODE_REF is dropped when no entry for this
    // parent survives, else re-written to just the surviving entries.
    edits.push(if di_remaining.is_empty() {
        Edit::Delete(dir_item_key)
    } else {
        Edit::Upsert(dir_item_key, di_remaining)
    });
    edits.push(Edit::Delete(BtrfsKey::new(
        parent_ino,
        format::DIR_INDEX_KEY,
        dir_index,
    )));
    if ref_remaining.is_empty() {
        edits.push(Edit::Delete(ref_key));
    } else {
        edits.push(Edit::Upsert(ref_key, ref_remaining));
    }
    if last_link {
        edits.push(Edit::Delete(BtrfsKey::new(
            child_ino,
            format::INODE_ITEM_KEY,
            0,
        )));
        for off in ed_offsets {
            edits.push(Edit::Delete(BtrfsKey::new(
                child_ino,
                format::EXTENT_DATA_KEY,
                off,
            )));
        }
        edits.extend(xattr_keys.into_iter().map(Edit::Delete));
    }

    commit_fs_edits(vol, gen, alloc, &edits, dropped_data, Vec::new()).await?;
    Ok(())
}

/// On-disk teardown prepared for an existing rename destination.
///
/// A last-link target owns its inode items and is reclaimed completely. A
/// hardlinked file loses only the overwritten name: its packed `INODE_REF`,
/// inode link count, data and xattrs otherwise survive.
struct RenameTarget {
    ino: u64,
    dir_index_key: BtrfsKey,
    ref_key: BtrfsKey,
    ref_remaining: Vec<u8>,
    inode_update: Option<Vec<u8>>,
    extent_offsets: Vec<u64>,
    xattr_keys: Vec<BtrfsKey>,
    dropped_data: Vec<DataRefId>,
}

impl RenameTarget {
    fn append_edits(self, edits: &mut Vec<Edit>) {
        edits.push(Edit::Delete(self.dir_index_key));
        edits.push(if self.ref_remaining.is_empty() {
            Edit::Delete(self.ref_key)
        } else {
            Edit::Upsert(self.ref_key, self.ref_remaining)
        });
        if let Some(inode) = self.inode_update {
            edits.push(Edit::Upsert(
                BtrfsKey::new(self.ino, format::INODE_ITEM_KEY, 0),
                inode,
            ));
        } else {
            edits.push(Edit::Delete(BtrfsKey::new(
                self.ino,
                format::INODE_ITEM_KEY,
                0,
            )));
            edits.extend(self.extent_offsets.into_iter().map(|offset| {
                Edit::Delete(BtrfsKey::new(self.ino, format::EXTENT_DATA_KEY, offset))
            }));
            edits.extend(self.xattr_keys.into_iter().map(Edit::Delete));
        }
    }
}

async fn prepare_rename_target<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    parent_ino: u64,
    name: &str,
    entry: &DirEntry,
    source_is_dir: bool,
    gen: u64,
) -> Result<RenameTarget, FsError> {
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported); // subvolume mount point
    }
    let ino = entry.location.objectid;
    let target_is_dir = entry.ftype == format::FT_DIR;
    if source_is_dir != target_is_dir {
        return Err(FsError::InvalidData); // EISDIR / ENOTDIR
    }
    let mut inode_body =
        btree::find_item(vol, fs_root, &BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0))
            .await?
            .ok_or(FsError::NotFound)?;
    let inode = InodeItem::decode(&inode_body)?;
    if inode.is_dir() != target_is_dir {
        return Err(FsError::InvalidData);
    }
    let last_link = inode.nlink <= 1;
    if target_is_dir && !last_link {
        return Err(FsError::InvalidData); // btrfs directories cannot be hardlinked
    }

    let ref_key = BtrfsKey::new(ino, format::INODE_REF_KEY, parent_ino);
    let ref_body = btree::find_item(vol, fs_root, &ref_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let (dir_index, ref_remaining) = inode_ref_remove(&ref_body, name.as_bytes())?;

    let mut extent_offsets = Vec::new();
    let mut xattr_keys = Vec::new();
    let mut dropped_data = Vec::new();
    let inode_update = if last_link {
        let mut cursor = btree::Cursor::seek(vol, fs_root, &BtrfsKey::new(ino, 0, 0)).await?;
        while let Some((key, body)) = cursor.current()? {
            if key.objectid != ino {
                break;
            }
            match key.item_type {
                format::INODE_ITEM_KEY | format::INODE_REF_KEY => {}
                format::XATTR_ITEM_KEY => xattr_keys.push(key),
                format::DIR_ITEM_KEY | format::DIR_INDEX_KEY => return Err(FsError::Busy),
                format::EXTENT_DATA_KEY if !target_is_dir => {
                    extent_offsets.push(key.offset);
                    if body.len() >= 53 && body[20] != format::FILE_EXTENT_INLINE {
                        let bytenr = le64(body, 21)?;
                        let len = le64(body, 29)?;
                        if bytenr != 0 {
                            dropped_data.push(DataRefId {
                                bytenr,
                                len,
                                ref_root: vol.fs_tree_id(),
                                objectid: ino,
                                offset: key
                                    .offset
                                    .checked_sub(le64(body, 37)?)
                                    .ok_or(FsError::InvalidData)?,
                            });
                        }
                    }
                }
                _ => return Err(FsError::Unsupported),
            }
            cursor.advance().await?;
        }
        None
    } else {
        inode_body[8..16].copy_from_slice(&gen.to_le_bytes());
        inode_body[40..44].copy_from_slice(&(inode.nlink - 1).to_le_bytes());
        Some(inode_body)
    };

    Ok(RenameTarget {
        ino,
        dir_index_key: BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, dir_index),
        ref_key,
        ref_remaining,
        inode_update,
        extent_offsets,
        xattr_keys,
        dropped_data,
    })
}

/// Remove the empty subdirectory `name` from directory `parent_ino` (default
/// subvolume) via a COW mini-transaction.
///
/// Scope (else the noted error): the child must be a directory (`InvalidData`
/// otherwise — use `unlink`), reached by a single `INODE_REF` and a
/// a `DIR_ITEM`, and **empty** — any `DIR_ITEM`/`DIR_INDEX` child makes it
/// `Busy`. Hash-colliding peer names in the parent bucket are preserved. Xattrs
/// are deleted with the inode; other item types remain unsupported.
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

    // Resolve the exact name inside its possibly colliding hash bucket.
    let dir_item_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(name_bytes)),
    );
    let di_body = btree::find_item(vol, fs_root, &dir_item_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let entry = find_dir_item(&di_body, name)?;
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported); // subvolume mount point
    }
    if entry.ftype != format::FT_DIR {
        return Err(FsError::InvalidData); // not a directory: use unlink
    }
    let child_ino = entry.location.objectid;
    let di_remaining = remove_dir_item(&di_body, name)?;

    let ci_body = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    if !InodeItem::decode(&ci_body)?.is_dir() {
        return Err(FsError::InvalidData);
    }

    // The directory must be empty. A DIR_ITEM/DIR_INDEX child means non-empty
    // (`Busy`). XATTR_ITEMs belong solely to this inode and are removed in the
    // same transaction; any other per-inode item remains out of scope.
    let mut xattr_keys = Vec::new();
    let mut cursor = btree::Cursor::seek(vol, fs_root, &BtrfsKey::new(child_ino, 0, 0)).await?;
    while let Some((k, _)) = cursor.current()? {
        if k.objectid != child_ino {
            break;
        }
        match k.item_type {
            format::INODE_ITEM_KEY | format::INODE_REF_KEY => {}
            format::XATTR_ITEM_KEY => xattr_keys.push(k),
            format::DIR_ITEM_KEY | format::DIR_INDEX_KEY => return Err(FsError::Busy),
            _ => return Err(FsError::Unsupported),
        }
        cursor.advance().await?;
    }

    // The child's INODE_REF back to this dir gives the DIR_INDEX offset.
    let ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, parent_ino);
    let ref_body = btree::find_item(vol, fs_root, &ref_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let (dir_index, single_ref) = inode_ref_index(&ref_body, name_bytes)?;
    if !single_ref {
        return Err(FsError::Unsupported);
    }

    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    // Shrink the parent dir inode by this entry's name (counted twice); bump
    // transid + sequence. The parent's nlink is unchanged (btrfs dirs, nlink 1).
    let mut pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    let psize = le64(&pinode, 16)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    pinode[16..24].copy_from_slice(
        &psize
            .saturating_sub(2 * name_bytes.len() as u64)
            .to_le_bytes(),
    );
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes());

    // Delete the child's INODE_ITEM + INODE_REF and the parent's DIR_ITEM +
    // DIR_INDEX.
    let mut edits = alloc::vec![
        Edit::Upsert(BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0), pinode,),
        if di_remaining.is_empty() {
            Edit::Delete(dir_item_key)
        } else {
            Edit::Upsert(dir_item_key, di_remaining)
        },
        Edit::Delete(BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, dir_index)),
        Edit::Delete(ref_key),
        Edit::Delete(BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0)),
    ];
    edits.extend(xattr_keys.into_iter().map(Edit::Delete));

    commit_fs_edits(vol, gen, alloc, &edits, Vec::new(), Vec::new()).await?;
    Ok(())
}

/// Rename entry `old_name` to `new_name` within directory `parent_ino` (default
/// subvolume) via a COW mini-transaction. Works for a file or a directory — the
/// source inode, its data and its link count are untouched; only its directory
/// entries and back-ref are re-keyed. If `new_name` already exists, it is
/// atomically replaced (its inode removed and, for a file, its data extents +
/// checksums freed) — the `QSaveFile`/`rename`-onto-target pattern.
///
/// Scope (else the noted error): same directory only. Overwrite requires the
/// same kind (dir↔dir / file↔file, else `InvalidData`); a directory target must
/// be empty (`Busy`). Hardlinked file targets lose just the overwritten name,
/// and xattrs are preserved or reclaimed with their inode. Colliding peer names
/// and packed hardlink refs are preserved.
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

    // Resolve the exact source record inside its hash bucket.
    let old_di_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(old_bytes)),
    );
    let old_di_body = btree::find_item(vol, fs_root, &old_di_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let entry = find_dir_item(&old_di_body, old_name)?;
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported); // subvolume mount point
    }
    let child_ino = entry.location.objectid;
    let ftype = entry.ftype;
    let source_is_dir = ftype == format::FT_DIR;
    let gen = vol.superblock().generation + 1;

    // Resolve the destination. If it already exists, gather what removing it
    // entails (an empty directory, or a file whose data + checksums we free).
    let new_di_key = BtrfsKey::new(
        parent_ino,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(new_bytes)),
    );
    let mut target: Option<RenameTarget> = None;
    let new_di_body = btree::find_item(vol, fs_root, &new_di_key).await?;
    let target_entry = match &new_di_body {
        Some(body) => decode_dir_items(body)?
            .into_iter()
            .find(|candidate| candidate.name == new_name),
        None => None,
    };
    if let Some(t) = target_entry {
        // POSIX: renaming one hardlink over another name for the same inode is
        // successful and leaves both names untouched.
        if t.location.objectid == child_ino && t.location.item_type == format::INODE_ITEM_KEY {
            return Ok(());
        }
        target = Some(
            prepare_rename_target(vol, fs_root, parent_ino, new_name, &t, source_is_dir, gen)
                .await?,
        );
    }
    let overwrite = target.is_some();
    let dropped_data = target
        .as_mut()
        .map_or_else(Vec::new, |target| core::mem::take(&mut target.dropped_data));

    // Re-key only this source name inside its potentially packed INODE_REF.
    let ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, parent_ino);
    let ref_body = btree::find_item(vol, fs_root, &ref_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let (old_index, mut ref_remaining) = inode_ref_remove(&ref_body, old_bytes)?;
    let new_index = next_dir_index(vol, fs_root, parent_ino).await?;
    ref_remaining.extend_from_slice(&inode_ref(new_index, new_bytes));

    let alloc = Allocator::build(vol).await?;

    // Adjust the parent dir `i_size` (each name counts twice: DIR_ITEM +
    // DIR_INDEX); bump transid + sequence. A plain rename swaps old→new name; an
    // overwrite additionally drops the target's (equal-length) `new` name, so the
    // net change is just the loss of the source's `old` name.
    let mut pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
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

    // Re-key the source into the new name at record granularity. Source and
    // destination can even be different names in the same collision bucket.
    let di = dir_item_body(child_ino, gen, ftype, new_bytes);
    let mut edits = alloc::vec![
        Edit::Upsert(BtrfsKey::new(parent_ino, format::INODE_ITEM_KEY, 0), pinode),
        Edit::Delete(BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, old_index)),
        Edit::Upsert(
            BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, new_index),
            di.clone()
        ),
        Edit::Upsert(ref_key, ref_remaining),
    ];
    if old_di_key == new_di_key {
        let mut bucket = remove_dir_item(&old_di_body, old_name)?;
        if overwrite {
            bucket = remove_dir_item(&bucket, new_name)?;
        }
        bucket = append_dir_item(Some(&bucket), new_name, &di)?;
        edits.push(Edit::Upsert(old_di_key, bucket));
    } else {
        let old_bucket = remove_dir_item(&old_di_body, old_name)?;
        edits.push(if old_bucket.is_empty() {
            Edit::Delete(old_di_key)
        } else {
            Edit::Upsert(old_di_key, old_bucket)
        });
        let mut new_bucket = new_di_body.unwrap_or_default();
        if overwrite {
            new_bucket = remove_dir_item(&new_bucket, new_name)?;
        }
        new_bucket = append_dir_item(Some(&new_bucket), new_name, &di)?;
        edits.push(Edit::Upsert(new_di_key, new_bucket));
    }
    if let Some(target) = target {
        target.append_edits(&mut edits);
    }

    commit_fs_edits(vol, gen, alloc, &edits, dropped_data, Vec::new()).await?;
    Ok(())
}

/// Whether `ancestor` is `node` itself or one of its ancestors, walking up the
/// `INODE_REF` chain (each `INODE_REF` key's offset is the parent inode) to the
/// root directory. Bounded against a corrupted cyclic chain. Used to refuse
/// moving a directory into its own subtree.
async fn is_ancestor_or_self<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fs_root: u64,
    ancestor: u64,
    start: u64,
) -> Result<bool, FsError> {
    let mut node = start;
    for _ in 0..64 {
        if node == ancestor {
            return Ok(true);
        }
        if node == format::FIRST_FREE_OBJECTID {
            return Ok(false); // reached the subvolume root
        }
        // The inode's first INODE_REF names a parent (its key offset).
        let cursor =
            btree::Cursor::seek(vol, fs_root, &BtrfsKey::new(node, format::INODE_REF_KEY, 0))
                .await?;
        match cursor.current()? {
            Some((k, _)) if k.objectid == node && k.item_type == format::INODE_REF_KEY => {
                node = k.offset;
            }
            _ => return Ok(false),
        }
    }
    Ok(false)
}

/// Move entry `old_name` from directory `old_parent` to `new_name` in a
/// *different* directory `new_parent` (both in the mounted subvolume) via one COW
/// mini-transaction. Re-keys the moved inode's `INODE_REF` from the old parent to
/// the new, moves its directory entries, and adjusts both parents' `i_size`. If
/// `new_name` already exists it is atomically replaced (same rules as the
/// same-directory overwrite). Both parents and the moved inode share the single
/// fs leaf.
///
/// Scope (else the noted error): `new_parent != old_parent`; a directory may not
/// move into its own subtree (`InvalidData`); an overwrite target must match kind
/// (`InvalidData`) and a directory target must be empty (`Busy`). Hardlinked
/// files and xattrs follow the same preservation/reclamation rules as same-dir
/// rename. Colliding peer names and packed hardlink refs are preserved.
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

    // Resolve the source in the old parent.
    let old_di_key = BtrfsKey::new(
        old_parent,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(old_bytes)),
    );
    let old_di_body = btree::find_item(vol, fs_root, &old_di_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let entry = find_dir_item(&old_di_body, old_name)?;
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported);
    }
    let child_ino = entry.location.objectid;
    let ftype = entry.ftype;
    let source_is_dir = ftype == format::FT_DIR;
    let gen = vol.superblock().generation + 1;

    // A directory must not move into itself or a descendant (would orphan a loop).
    if source_is_dir && is_ancestor_or_self(vol, fs_root, child_ino, new_parent).await? {
        return Err(FsError::InvalidData);
    }

    // Remove only this name from the source's possibly packed old-parent ref.
    let old_ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, old_parent);
    let old_ref_body = btree::find_item(vol, fs_root, &old_ref_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let (old_index, old_ref_remaining) = inode_ref_remove(&old_ref_body, old_bytes)?;

    // Resolve the destination in the new parent (may exist -> overwrite).
    let new_di_key = BtrfsKey::new(
        new_parent,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(new_bytes)),
    );
    let mut target: Option<RenameTarget> = None;
    let new_di_body = btree::find_item(vol, fs_root, &new_di_key).await?;
    let target_entry = match &new_di_body {
        Some(body) => decode_dir_items(body)?
            .into_iter()
            .find(|candidate| candidate.name == new_name),
        None => None,
    };
    if let Some(t) = target_entry {
        if t.location.objectid == child_ino && t.location.item_type == format::INODE_ITEM_KEY {
            return Ok(());
        }
        target = Some(
            prepare_rename_target(vol, fs_root, new_parent, new_name, &t, source_is_dir, gen)
                .await?,
        );
    }
    let overwrite = target.is_some();
    let dropped_data = target
        .as_mut()
        .map_or_else(Vec::new, |target| core::mem::take(&mut target.dropped_data));
    let new_index = next_dir_index(vol, fs_root, new_parent).await?;

    // Preserve any other source links already present in the destination dir.
    let new_ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, new_parent);
    let mut new_ref_body = btree::find_item(vol, fs_root, &new_ref_key)
        .await?
        .unwrap_or_default();
    new_ref_body.extend_from_slice(&inode_ref(new_index, new_bytes));

    let alloc = Allocator::build(vol).await?;

    // Both parents' `i_size` change: the old parent loses the source name; the new
    // parent gains it (net zero on an overwrite, whose equal-length target name is
    // reused). Bump transid + sequence. Build each as an Upsert.
    let bumped_dir_inode = |ino: &mut Vec<u8>, delta: i64| -> Result<(), FsError> {
        let sz = le64(ino, 16)? as i64;
        ino[8..16].copy_from_slice(&gen.to_le_bytes());
        ino[16..24].copy_from_slice(&(sz + delta).max(0).to_le_bytes());
        let seq = le64(ino, 72)?;
        ino[72..80].copy_from_slice(&(seq + 1).to_le_bytes());
        Ok(())
    };
    let mut old_pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(old_parent, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    bumped_dir_inode(&mut old_pinode, -2 * old_bytes.len() as i64)?;
    let mut new_pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(new_parent, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    bumped_dir_inode(
        &mut new_pinode,
        if overwrite {
            0
        } else {
            2 * new_bytes.len() as i64
        },
    )?;

    // Re-key the source under the new parent at record granularity, retaining
    // collision peers in both parent buckets.
    let di = dir_item_body(child_ino, gen, ftype, new_bytes);
    let mut edits = alloc::vec![
        Edit::Upsert(
            BtrfsKey::new(old_parent, format::INODE_ITEM_KEY, 0),
            old_pinode
        ),
        Edit::Upsert(
            BtrfsKey::new(new_parent, format::INODE_ITEM_KEY, 0),
            new_pinode
        ),
        Edit::Delete(BtrfsKey::new(old_parent, format::DIR_INDEX_KEY, old_index)),
        if old_ref_remaining.is_empty() {
            Edit::Delete(old_ref_key)
        } else {
            Edit::Upsert(old_ref_key, old_ref_remaining)
        },
        Edit::Upsert(
            BtrfsKey::new(new_parent, format::DIR_INDEX_KEY, new_index),
            di.clone()
        ),
        Edit::Upsert(new_ref_key, new_ref_body),
    ];
    let old_bucket = remove_dir_item(&old_di_body, old_name)?;
    edits.push(if old_bucket.is_empty() {
        Edit::Delete(old_di_key)
    } else {
        Edit::Upsert(old_di_key, old_bucket)
    });
    let mut new_bucket = new_di_body.unwrap_or_default();
    if overwrite {
        new_bucket = remove_dir_item(&new_bucket, new_name)?;
    }
    new_bucket = append_dir_item(Some(&new_bucket), new_name, &di)?;
    edits.push(Edit::Upsert(new_di_key, new_bucket));
    if let Some(target) = target {
        target.append_edits(&mut edits);
    }

    commit_fs_edits(vol, gen, alloc, &edits, dropped_data, Vec::new()).await?;
    Ok(())
}

/// Create a hard link `new_name` in directory `target_parent` to the inode that
/// `old_name` names in directory `source_parent` (both in the mounted subvolume)
/// via one COW mini-transaction: a new DIR_ITEM + DIR_INDEX in the target dir, an
/// added `INODE_REF` entry (appended to the existing item when the inode already
/// links into that dir, else a fresh item), the inode's `nlink` bumped, and the
/// target dir's `i_size` grown.
///
/// Scope (else the noted error): one mounted subvolume; the source must not be a
/// directory (`PermissionDenied` — hard-linking a directory is EPERM) and
/// `new_name` must be free. Hash-colliding peer names are preserved.
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

    // Resolve the source; hard links to directories are forbidden.
    let old_di_key = BtrfsKey::new(
        source_parent,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(old_bytes)),
    );
    let old_di_body = btree::find_item(vol, fs_root, &old_di_key)
        .await?
        .ok_or(FsError::NotFound)?;
    let entry = find_dir_item(&old_di_body, old_name)?;
    if entry.location.item_type != format::INODE_ITEM_KEY {
        return Err(FsError::Unsupported);
    }
    if entry.ftype == format::FT_DIR {
        return Err(FsError::PermissionDenied); // EPERM: no hard links to directories
    }
    let child_ino = entry.location.objectid;
    let child_ftype = entry.ftype;

    // The destination name must be free; a different colliding name is retained.
    let new_di_key = BtrfsKey::new(
        target_parent,
        format::DIR_ITEM_KEY,
        u64::from(name_hash(new_bytes)),
    );
    let target_bucket = btree::find_item(vol, fs_root, &new_di_key).await?;
    if target_bucket
        .as_deref()
        .is_some_and(|body| find_dir_item(body, new_name).is_ok())
    {
        return Err(FsError::InvalidData);
    }

    let new_index = next_dir_index(vol, fs_root, target_parent).await?;
    let gen = vol.superblock().generation + 1;
    let alloc = Allocator::build(vol).await?;

    // Bump the linked inode's nlink; stamp its transid.
    let mut cinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    let nlink = format::le32(&cinode, 40)?;
    cinode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    cinode[40..44].copy_from_slice(&(nlink + 1).to_le_bytes());

    // Grow the target dir's i_size by the new name (counted twice); transid+seq.
    let mut pinode = btree::find_item(
        vol,
        fs_root,
        &BtrfsKey::new(target_parent, format::INODE_ITEM_KEY, 0),
    )
    .await?
    .ok_or(FsError::NotFound)?;
    let psize = le64(&pinode, 16)?;
    pinode[8..16].copy_from_slice(&gen.to_le_bytes());
    pinode[16..24].copy_from_slice(&(psize + 2 * new_bytes.len() as u64).to_le_bytes());
    let pseq = le64(&pinode, 72)?;
    pinode[72..80].copy_from_slice(&(pseq + 1).to_le_bytes());

    // Add the INODE_REF entry: append to the existing (child, INODE_REF, parent)
    // item if the inode already links into this dir, else insert a fresh item.
    let ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, target_parent);
    let mut ref_body = btree::find_item(vol, fs_root, &ref_key)
        .await?
        .unwrap_or_default();
    ref_body.extend_from_slice(&inode_ref(new_index, new_bytes));

    // Add the directory entries pointing at the linked inode.
    let di = dir_item_body(child_ino, gen, child_ftype, new_bytes);
    let di_bucket = append_dir_item(target_bucket.as_deref(), new_name, &di)?;
    let edits = alloc::vec![
        Edit::Upsert(BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0), cinode),
        Edit::Upsert(
            BtrfsKey::new(target_parent, format::INODE_ITEM_KEY, 0),
            pinode
        ),
        Edit::Upsert(ref_key, ref_body),
        Edit::Upsert(new_di_key, di_bucket),
        Edit::Upsert(
            BtrfsKey::new(target_parent, format::DIR_INDEX_KEY, new_index),
            di
        ),
    ];

    commit_fs_edits(vol, gen, alloc, &edits, Vec::new(), Vec::new()).await?;
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

/// Set (create or replace) extended attribute `name` = `value` on inode `ino`
/// (mounted subvolume). `flags` honours Linux `XATTR_CREATE` (1) / `XATTR_REPLACE`
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

    let (fs_root, _) = vol.fs_tree_root();
    let gen = vol.superblock().generation + 1;
    let existing = btree::find_item(vol, fs_root, &key).await?;

    // Rebuild the (possibly shared) item body, dropping this name if present so it
    // is re-added with the new value; other names on the same hash are preserved.
    let mut body = Vec::new();
    let mut had_name = false;
    if let Some(b) = &existing {
        for e in decode_dir_items(b)? {
            if e.name == name {
                had_name = true;
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

    let alloc = Allocator::build(vol).await?;
    commit_fs_edits(
        vol,
        gen,
        alloc,
        &[Edit::Upsert(key, body)],
        Vec::new(),
        Vec::new(),
    )
    .await
}

/// Remove extended attribute `name` from inode `ino` (mounted subvolume). Deletes
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

    let (fs_root, _) = vol.fs_tree_root();
    let gen = vol.superblock().generation + 1;
    let body_in = btree::find_item(vol, fs_root, &key)
        .await?
        .ok_or(FsError::NotFound)?;
    let entries = decode_dir_items(&body_in)?;
    if !entries.iter().any(|e| e.name == name) {
        return Err(FsError::NotFound); // ENODATA
    }
    let mut body = Vec::new();
    for e in &entries {
        if e.name != name {
            body.extend_from_slice(&xattr_entry(gen, e.name.as_bytes(), &e.value));
        }
    }
    // Drop the whole item when this was its only name, else re-write the rest.
    let edit = if body.is_empty() {
        Edit::Delete(key)
    } else {
        Edit::Upsert(key, body)
    };

    let alloc = Allocator::build(vol).await?;
    commit_fs_edits(vol, gen, alloc, &[edit], Vec::new(), Vec::new()).await
}

// ── Tree-log (fsync) ───────────────────────────────────────────────

/// On-disk size of a `struct btrfs_root_item`.
const ROOT_ITEM_SIZE: usize = 439;

/// A minimal `btrfs_root_item` naming the tree rooted at `(bytenr, level)` at
/// generation `gen`. Only the fields log replay reads (bytenr @176, level @238)
/// plus the generations and a positive refs count are set; the rest stay zero.
fn log_root_item(gen: u64, bytenr: u64, level: u8) -> Vec<u8> {
    let mut v = alloc::vec![0u8; ROOT_ITEM_SIZE];
    v[160..168].copy_from_slice(&gen.to_le_bytes()); // generation
    v[176..184].copy_from_slice(&bytenr.to_le_bytes()); // bytenr
    v[216..220].copy_from_slice(&1u32.to_le_bytes()); // refs
    v[238] = level; // level
    v[239..247].copy_from_slice(&gen.to_le_bytes()); // generation_v2
    v
}

/// Pack `items` (key-ordered) into a tree whose node headers record `owner`,
/// allocate its blocks from `alloc`, and write them. Returns `(root, level)`.
async fn write_owned_tree<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    alloc: &mut Allocator,
    gen: u64,
    owner: u64,
    items: &[(BtrfsKey, Vec<u8>)],
) -> Result<(u64, u8), FsError> {
    // A header template stamped with the tree's owner; capacity holds every item.
    let mut header = vol.read_node(vol.fs_tree_root().0).await?[..HEADER_SIZE].to_vec();
    header[HDR_OWNER..HDR_OWNER + 8].copy_from_slice(&owner.to_le_bytes());
    let body_total: usize = items.iter().map(|(_, b)| b.len()).sum();
    let capacity = HEADER_SIZE + items.len() * LEAF_ITEM_SIZE + body_total + HEADER_SIZE;
    let refs: Vec<(BtrfsKey, &[u8])> = items.iter().map(|(k, b)| (*k, b.as_slice())).collect();
    let leaf = pack_leaf(&header, &refs, capacity);
    let groups = group_items(vol, &leaf)?;
    let addrs = alloc_nodes(alloc, vol, tree_block_count(groups.len(), vol.nodesize()))?;
    let (nodes, root, level) = pack_tree_at(vol, &leaf, &groups, &addrs, gen)?;
    for (addr, buf) in &nodes {
        vol.write_logical(*addr, buf).await?;
    }
    Ok((root, level))
}

/// Write a tree-log recording `items` for the mounted subvolume and point the
/// superblock at it **without** committing them to the fs tree — the fsync fast
/// path a subsequent mount replays ([`replay_log`]). `items` are fs-tree items
/// (keyed the same) to merge into the fs tree on replay, plus optional standard
/// `DIR_LOG_INDEX` authoritative ranges used to represent directory deletions.
///
/// The log's blocks come from currently-free space (like real btrfs's pinned log
/// extents) and are deliberately *not* recorded in the extent/free-space trees, so
/// this must be followed by a mount+replay — or a full commit that clears the log —
/// before any other allocation could reuse that space.
pub async fn write_log<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    items: &[(BtrfsKey, Vec<u8>)],
) -> Result<(), FsError> {
    let gen = vol.superblock().generation + 1;
    let mut alloc = Allocator::build(vol).await?;

    // The subvolume's log tree, then the log-root tree mapping its root id to it.
    let (log_root, log_level) =
        write_owned_tree(vol, &mut alloc, gen, format::TREE_LOG_OBJECTID, items).await?;
    let root_key = BtrfsKey::new(
        format::TREE_LOG_OBJECTID,
        format::ROOT_ITEM_KEY,
        vol.fs_tree_id(),
    );
    let root_items = [(root_key, log_root_item(gen, log_root, log_level))];
    let (log_root_tree, log_root_tree_level) =
        write_owned_tree(vol, &mut alloc, gen, format::TREE_LOG_OBJECTID, &root_items).await?;

    // Point the superblock at the log-root tree. The committed generation is left
    // unchanged: the log is an overlay on it, applied at mount.
    let mut raw = vol.read_raw_superblock().await?;
    raw[format::OFF_LOG_ROOT..format::OFF_LOG_ROOT + 8]
        .copy_from_slice(&log_root_tree.to_le_bytes());
    raw[format::OFF_LOG_ROOT_TRANSID..format::OFF_LOG_ROOT_TRANSID + 8]
        .copy_from_slice(&gen.to_le_bytes());
    raw[format::OFF_LOG_ROOT_LEVEL] = log_root_tree_level;
    crate::checksum::stamp_block(vol.csum_type(), &mut raw)?;
    vol.flush().await;
    vol.write_superblock(&raw).await?;
    Ok(())
}

/// If the superblock names an unreplayed tree-log, merge it into the fs tree and
/// clear the pointer — btrfs crash recovery, run once at mount. Returns whether a
/// log was replayed.
///
/// Ordinary items are `Upsert`ed into the fs tree. Before those upserts, modern
/// `DIR_LOG_INDEX` authoritative ranges remove each committed `DIR_INDEX` entry
/// whose index/name is absent from the log, using the normal unlink/rmdir COW
/// paths so inode refs, link counts, data extents, checksums and parent metadata
/// stay consistent. Log-only range items are never copied into the FS tree.
async fn replay_log_items<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    log_items: Vec<(BtrfsKey, Vec<u8>)>,
) -> Result<(), FsError> {
    // Current Linux kernels log directory indexes only. Decode them once up
    // front both to validate the log before applying ranges and to make
    // same-index/name authority checks unambiguous.
    let mut logged_dir_indexes = Vec::new();
    for (key, body) in &log_items {
        if key.item_type != format::DIR_INDEX_KEY {
            continue;
        }
        let entries = decode_dir_items(body)?;
        if entries.len() != 1 {
            return Err(FsError::InvalidData);
        }
        logged_dir_indexes.push((key.objectid, key.offset, entries[0].name.clone()));
    }

    // Linux tree logs describe directory removals indirectly: each range says
    // the log is authoritative for DIR_INDEX offsets [start, end]. A committed
    // entry in that range which has no same-index/name entry in the log was
    // deleted before fsync and must be unlinked during recovery.
    let mut deletions = Vec::new();
    for (range_key, range_body) in &log_items {
        if range_key.item_type != format::DIR_LOG_INDEX_KEY {
            continue;
        }
        if range_body.len() != 8 {
            return Err(FsError::InvalidData);
        }
        let range_end = le64(range_body, 0)?;
        if range_end < range_key.offset {
            return Err(FsError::InvalidData);
        }
        let (fs_root, _) = vol.fs_tree_root();
        for (key, body) in
            btree::collect_for(vol, fs_root, range_key.objectid, format::DIR_INDEX_KEY).await?
        {
            if key.offset < range_key.offset || key.offset > range_end {
                continue;
            }
            let entries = decode_dir_items(&body)?;
            if entries.len() != 1 {
                return Err(FsError::InvalidData); // DIR_INDEX offsets are unique
            }
            let entry = &entries[0];
            let present = logged_dir_indexes.iter().any(|(dir, index, name)| {
                *dir == key.objectid && *index == key.offset && *name == entry.name
            });
            if !present
                && !deletions
                    .iter()
                    .any(|(dir, index, _, _)| *dir == key.objectid && *index == key.offset)
            {
                deletions.push((key.objectid, key.offset, entry.name.clone(), entry.ftype));
            }
        }
    }
    deletions.sort_unstable_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    for (parent, _index, name, ftype) in deletions {
        let result = if ftype == format::FT_DIR {
            rmdir_dir(vol, parent, &name).await
        } else {
            unlink_file(vol, parent, &name).await
        };
        match result {
            Ok(()) | Err(FsError::NotFound) => {}
            Err(e) => return Err(e),
        }
    }

    // Merge ordinary logged items after deletions. Range markers are log-only
    // metadata and must never appear in the committed FS tree.
    let mut edits = Vec::new();
    for (key, body) in log_items {
        if key.item_type == format::DIR_LOG_ITEM_KEY || key.item_type == format::DIR_LOG_INDEX_KEY {
            continue;
        }
        edits.push(Edit::Upsert(key, body.clone()));
        if key.item_type != format::DIR_INDEX_KEY {
            continue;
        }

        // Linux no longer logs the hash-keyed DIR_ITEM twin. Reconstruct it
        // from the logged DIR_INDEX body so lookup and readdir remain coherent.
        // Merge at record granularity because multiple logged/existing names can
        // share the same CRC32C hash bucket.
        let entries = decode_dir_items(&body)?;
        if entries.len() != 1 {
            return Err(FsError::InvalidData);
        }
        let entry = &entries[0];
        let dir_item_key = BtrfsKey::new(
            key.objectid,
            format::DIR_ITEM_KEY,
            u64::from(name_hash(entry.name.as_bytes())),
        );
        let (fs_root, _) = vol.fs_tree_root();
        let pending = edits.iter().rposition(|edit| edit.key() == &dir_item_key);
        let mut bucket = match pending.map(|slot| match &edits[slot] {
            Edit::Upsert(_, pending_body) => pending_body.clone(),
            Edit::Delete(_) => Vec::new(),
        }) {
            Some(body) => body,
            None => btree::find_item(vol, fs_root, &dir_item_key)
                .await?
                .unwrap_or_default(),
        };
        if find_dir_item(&bucket, &entry.name).is_ok() {
            bucket = remove_dir_item(&bucket, &entry.name)?;
        }
        bucket = append_dir_item(Some(&bucket), &entry.name, &body)?;
        let edit = Edit::Upsert(dir_item_key, bucket);
        if let Some(slot) = pending {
            edits[slot] = edit;
        } else {
            edits.push(edit);
        }
    }
    if !edits.is_empty() {
        let gen = vol.superblock().generation + 1;
        let alloc = Allocator::build(vol).await?;
        commit_fs_edits(vol, gen, alloc, &edits, Vec::new(), Vec::new()).await?;
    }

    Ok(())
}

/// Replay every subvolume mapping in the log-root tree. All log items are read
/// before the first transaction because log blocks are pinned-but-unaccounted
/// and may be reused by a replay commit's allocator.
pub async fn replay_log<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> Result<bool, FsError> {
    let sb = vol.superblock();
    if sb.log_root == 0 {
        return Ok(false);
    }
    let start = BtrfsKey::new(format::TREE_LOG_OBJECTID, format::ROOT_ITEM_KEY, 0);
    let mut cursor = btree::Cursor::seek(vol, sb.log_root, &start).await?;
    let mut logs = Vec::new();
    while let Some((key, root_item)) = cursor.current()? {
        if key.objectid != format::TREE_LOG_OBJECTID || key.item_type != format::ROOT_ITEM_KEY {
            break;
        }
        if root_item.len() < 239 {
            return Err(FsError::InvalidData);
        }
        let log_root = le64(root_item, 176)?;
        let mut items = Vec::new();
        let mut log_cursor = btree::Cursor::seek(vol, log_root, &BtrfsKey::new(0, 0, 0)).await?;
        while let Some((item_key, body)) = log_cursor.current()? {
            items.push((item_key, body.to_vec()));
            log_cursor.advance().await?;
        }
        logs.push((key.offset, items));
        cursor.advance().await?;
    }
    if logs.is_empty() {
        return Err(FsError::InvalidData);
    }

    let original_root = vol.fs_tree_id();
    for (root_id, items) in logs {
        if root_id != vol.fs_tree_id() {
            vol.switch_to_subvol(&crate::volume::Subvol::Id(root_id))
                .await?;
        }
        if !vol.supports_writes() {
            return Err(FsError::Unsupported);
        }
        replay_log_items(vol, items).await?;
    }
    if original_root != vol.fs_tree_id() {
        vol.switch_to_subvol(&crate::volume::Subvol::Id(original_root))
            .await?;
    }

    // Clear the log pointer only after every mapped root is authoritative.
    let mut raw = vol.read_raw_superblock().await?;
    raw[format::OFF_LOG_ROOT..format::OFF_LOG_ROOT + 8].copy_from_slice(&0u64.to_le_bytes());
    raw[format::OFF_LOG_ROOT_TRANSID..format::OFF_LOG_ROOT_TRANSID + 8]
        .copy_from_slice(&0u64.to_le_bytes());
    raw[format::OFF_LOG_ROOT_LEVEL] = 0;
    crate::checksum::stamp_block(vol.csum_type(), &mut raw)?;
    vol.flush().await;
    vol.write_superblock(&raw).await?;
    vol.clear_log_root();
    Ok(true)
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

    let bytes_used = total_block_group_used(vol, ext_root_addr).await?;
    let mut raw = vol.read_raw_superblock().await?;
    raw[72..80].copy_from_slice(&gen.to_le_bytes()); // generation
    raw[80..88].copy_from_slice(&root_root_addr.to_le_bytes()); // root
    raw[88..96].copy_from_slice(&chunk_root_addr.to_le_bytes()); // chunk_root
    raw[120..128].copy_from_slice(&bytes_used.to_le_bytes()); // bytes_used
    raw[164..172].copy_from_slice(&gen.to_le_bytes()); // chunk_root_generation
                                                       // Embedded dev_item.bytes_used (dev_item@201, bytes_used@+16).
    raw[217..225].copy_from_slice(&dev_used.to_le_bytes());
    crate::checksum::stamp_block(vol.csum_type(), &mut raw)?;
    vol.flush().await;
    vol.write_superblock(&raw).await?;
    vol.commit_chunk_root(chunk_root_addr, root_root_addr, gen);
    Ok(())
}
