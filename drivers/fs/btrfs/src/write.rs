//! Copy-on-write mutations: file writes (overwrite / partial / append / grow)
//! and namespace operations (`create` / `unlink`) in the default subvolume.
//!
//! All mutations share one closed-form COW mini-transaction ([`commit_txn`]):
//! given the fully-edited fs (and, for data changes, csum) leaves, it frees the
//! old blocks of every copied tree, records the new ones in the extent tree,
//! maintains the free-space tree, repoints the affected `ROOT_ITEM`s, writes
//! every node, and flips the superblock last. All touched trees must be single
//! leaves so every new block can be pre-allocated up front (the extent leaf then
//! records its own new block), sidestepping the delayed-ref loop real btrfs uses.
//!
//! Scope: a regular, uncompressed file that is empty (e.g. freshly `create`d) or
//! a single `EXTENT_DATA` at offset 0, in the default subvolume, on a volume
//! whose fs/csum/root/extent (and free-space, if present) trees are each a single
//! leaf (typical of a freshly-made small image). A write reads the current file,
//! applies the new bytes at any offset (growing past EOF as needed), and rewrites
//! the whole file as one new extent (inserting the first one for an empty file),
//! as a genuine copy-on-write mini-transaction that never mutates live data or
//! metadata in place. Because these trees are single leaves, every new block is
//! pre-allocated up front, letting the extent leaf record its own new block —
//! sidestepping the self-referential allocation loop full btrfs handles with
//! delayed refs. Per write it:
//!
//! 1. allocates + writes the new data extent, and its per-sector CRC32C **data
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
//! (free-space-tree) image. Bounds: single-leaf trees only (multi-level
//! → `Unsupported`), no node splitting (`NoSpace` on a full leaf), no new-chunk
//! allocation, no space reclaim (freed logical addresses aren't reused), extent-
//! mode free-space tracking only (a `FREE_SPACE_BITMAP` block group is out of
//! scope), and a 64 MiB superblock mirror is out of scope.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::allocator::{extent_high_water, BumpAllocator};
use crate::btree::{
    self, leaf_item_data, leaf_item_key, leaf_item_span, leaf_lower_bound, level, nritems,
    HEADER_SIZE,
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
fn stamp_node(buf: &mut [u8], addr: u64, gen: u64) {
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
/// gen,flags=DATA}` + inline `EXTENT_DATA_REF{root, objectid, offset=0, count=1}`.
fn ext_item_data(gen: u64, root: u64, objectid: u64) -> Vec<u8> {
    let mut v = alloc::vec![0u8; 53];
    v[0..8].copy_from_slice(&1u64.to_le_bytes());
    v[8..16].copy_from_slice(&gen.to_le_bytes());
    v[16..24].copy_from_slice(&EXTENT_FLAG_DATA.to_le_bytes());
    v[24] = EXTENT_DATA_REF_KEY;
    v[25..33].copy_from_slice(&root.to_le_bytes()); // ref root
    v[33..41].copy_from_slice(&objectid.to_le_bytes()); // ref objectid (inode)
    v[41..49].copy_from_slice(&0u64.to_le_bytes()); // ref offset
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

// ── Free-space tree (space_cache=v2), extent mode ──────────────────

/// Adjust a block group's `FREE_SPACE_INFO.extent_count` by `delta`.
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

/// Mark `[start, start+len)` USED in the free-space tree: carve it out of the
/// `FREE_SPACE_EXTENT` that contains it (leaving up to two remainders).
fn fst_mark_used(
    fst_leaf: &mut [u8],
    bg_start: u64,
    _bg_len: u64,
    start: u64,
    len: u64,
) -> Result<(), FsError> {
    let end = start + len;
    let n = nritems(fst_leaf)? as usize;
    let mut found: Option<(usize, u64, u64)> = None;
    for i in 0..n {
        let k = leaf_item_key(fst_leaf, i)?;
        if k.item_type == format::FREE_SPACE_BITMAP_KEY {
            return Err(FsError::Unsupported); // bitmap mode not supported
        }
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
    bg_start: u64,
    bg_len: u64,
    start: u64,
    len: u64,
) -> Result<(), FsError> {
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

/// Write `data` at byte `offset` into file `ino` via COW: read-modify-write the
/// whole file into one new extent, growing the file if the write extends past
/// its current end. Supports overwrite, partial write, append and grow.
pub async fn cow_write_file<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    inode: &InodeItem,
    offset: u64,
    data: &[u8],
) -> Result<usize, FsError> {
    // ── Preconditions ──────────────────────────────────────────────
    if !inode.is_regular() {
        return Err(FsError::Unsupported);
    }
    let (fs_root, fs_level) = vol.fs_tree_root();
    let (root_tree, _root_level) = vol.root_tree_root();

    // A zero-byte write changes nothing.
    if data.is_empty() {
        return Ok(0);
    }

    // The file must be either empty (no EXTENT_DATA — e.g. freshly `create`d) or
    // a single regular, uncompressed extent at offset 0, so its content is one
    // EXTENT_DATA item we can rewrite (or, for an empty file, first insert)
    // wholesale. `existing` is the old `(disk_bytenr, disk_num_bytes)` to free.
    let extents = btree::collect_for(vol, fs_root, ino, format::EXTENT_DATA_KEY).await?;
    let existing: Option<(u64, u64)> = match extents.len() {
        0 => None,
        1 => {
            let (ed_key, ed_body) = &extents[0];
            // btrfs_file_extent_item: ram_bytes@8, compression@16, type@20,
            // disk_bytenr@21, disk_num_bytes@29, extent_offset@37, num_bytes@45.
            if ed_key.offset != 0 || ed_body.len() < 53 {
                return Err(FsError::Unsupported);
            }
            if ed_body[16] != 0 || ed_body[20] != format::FILE_EXTENT_REG {
                return Err(FsError::Unsupported);
            }
            if le64(ed_body, 37)? != 0 {
                return Err(FsError::Unsupported); // points mid-shared-extent: out of scope
            }
            Some((le64(ed_body, 21)?, le64(ed_body, 29)?))
        }
        _ => return Err(FsError::Unsupported),
    };

    // ── 1. Read-modify-write the file content into one buffer ──────
    let old_size = inode.size;
    let end = offset
        .checked_add(data.len() as u64)
        .ok_or(FsError::InvalidData)?;
    let new_size = old_size.max(end);
    let sectorsize = u64::from(vol.sectorsize());
    let disk_len = align_up(new_size, sectorsize).max(sectorsize);

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

    // ── 2. Set up the mini-transaction (single-leaf trees only) ────
    // Full extent-tree accounting is only tractable here when the fs, csum,
    // root and extent trees are each a single leaf: we can then pre-allocate
    // every new node and build them all — including the extent leaf's item for
    // its own new block — in one pass, sidestepping the self-referential
    // allocation loop that real btrfs handles with delayed refs.
    let old_fs = fs_root;
    let old_root = root_tree;
    let (old_csum, _csum_level) =
        roots::find_root(vol, root_tree, format::CSUM_TREE_OBJECTID).await?;
    let old_ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    // The free-space tree (space_cache=v2) is optional; maintain it when present.
    let old_fst = roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID)
        .await
        .ok()
        .map(|(r, _)| r);
    let old_data = existing.map(|(d, _)| d); // disk_bytenr of the freed extent
    let old_data_len = existing.map(|(_, l)| l).unwrap_or(0); // disk_num_bytes

    let mut fs_leaf = vol.read_node(old_fs).await?;
    let mut csum_leaf = vol.read_node(old_csum).await?;
    let root_leaf = vol.read_node(old_root).await?;
    let ext_leaf = vol.read_node(old_ext).await?;
    let fst_leaf = match old_fst {
        Some(fst) => Some(vol.read_node(fst).await?),
        None => None,
    };
    for leaf in [&fs_leaf, &csum_leaf, &root_leaf, &ext_leaf] {
        if level(leaf)? != 0 {
            return Err(FsError::Unsupported); // multi-level trees not supported
        }
    }
    if let Some(fl) = &fst_leaf {
        if level(fl)? != 0 {
            return Err(FsError::Unsupported);
        }
    }

    let gen = vol.superblock().generation + 1;
    let high_water = extent_high_water(vol, old_ext)
        .await?
        .max(vol.alloc_floor());
    let mut alloc = BumpAllocator::new(high_water);

    // Pre-allocate every new block up front so cross-references resolve.
    let e_data = alloc.alloc_data(vol, disk_len)?;
    let n_fs = alloc.alloc_node(vol)?;
    let n_csum = alloc.alloc_node(vol)?;
    let n_ext = alloc.alloc_node(vol)?;
    let n_root = alloc.alloc_node(vol)?;
    let n_fst = if old_fst.is_some() {
        Some(alloc.alloc_node(vol)?)
    } else {
        None
    };
    // The whole new allocation is contiguous (bump allocator); its span is what
    // the free-space tree must mark used.
    let alloc_end = alloc.next();

    // ── 3. Write the data extent + its checksums ───────────────────
    let mut payload = buf;
    payload.resize(disk_len as usize, 0);
    vol.write_logical(e_data, &payload).await?;
    let csums = crate::csum::compute_csums(&payload, sectorsize as usize);

    // ── 4. Build the new fs leaf (point EXTENT_DATA at the new extent, update
    //       INODE). Replace the existing item, or insert one for an empty file.
    let new_ed = file_extent_reg(gen, e_data, disk_len);
    let ed_key = BtrfsKey::new(ino, format::EXTENT_DATA_KEY, 0);
    if let Some(slot) = leaf_find(&fs_leaf, &ed_key)? {
        leaf_replace_inplace(&mut fs_leaf, slot, &new_ed)?;
    } else {
        leaf_insert_sorted(&mut fs_leaf, &ed_key, &new_ed)?;
    }

    let inode_slot = leaf_find(&fs_leaf, &BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0))?
        .ok_or(FsError::NotFound)?;
    let mut new_inode = leaf_item_data(&fs_leaf, inode_slot)?.to_vec();
    new_inode[0..8].copy_from_slice(&gen.to_le_bytes()); // generation
    new_inode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    new_inode[16..24].copy_from_slice(&new_size.to_le_bytes()); // size
    new_inode[24..32].copy_from_slice(&disk_len.to_le_bytes()); // nbytes
    leaf_replace_inplace(&mut fs_leaf, inode_slot, &new_inode)?;

    // ── 5. Build the new csum leaf: drop the old extent's csums, add new ─
    // The old data extent is being freed, so its csum item must go too, else
    // `btrfs check` reports "csum exists but there is no extent record". An empty
    // file has no old extent to uncharge.
    if let Some(old_data) = old_data {
        if old_data != e_data {
            let old_csum_key = BtrfsKey::new(
                format::EXTENT_CSUM_OBJECTID,
                format::EXTENT_CSUM_KEY,
                old_data,
            );
            if let Some(slot) = leaf_find(&csum_leaf, &old_csum_key)? {
                leaf_delete(&mut csum_leaf, slot)?;
            }
        }
    }
    let csum_key = BtrfsKey::new(
        format::EXTENT_CSUM_OBJECTID,
        format::EXTENT_CSUM_KEY,
        e_data,
    );
    if let Some(slot) = leaf_find(&csum_leaf, &csum_key)? {
        leaf_replace_inplace(&mut csum_leaf, slot, &csums)?;
    } else {
        leaf_insert_sorted(&mut csum_leaf, &csum_key, &csums)?;
    }

    // ── 6-8. Commit: extent/free-space/root trees + superblock flip ─
    let _ = fs_level;
    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: CowLeaf::new(fs_leaf, old_fs, n_fs),
            csum: Some(CowLeaf::new(csum_leaf, old_csum, n_csum)),
            ext: CowLeaf::new(ext_leaf, old_ext, n_ext),
            root: CowLeaf::new(root_leaf, old_root, n_root),
            fst: fst_leaf.map(|leaf| CowLeaf::new(leaf, old_fst.unwrap(), n_fst.unwrap())),
            freed_data: old_data.map(|d| (d, old_data_len)).into_iter().collect(),
            new_data: alloc::vec![DataRef {
                bytenr: e_data,
                len: disk_len,
                ref_root: format::FS_TREE_OBJECTID,
                objectid: ino,
            }],
            data_used_delta: disk_len as i64 - old_data_len as i64,
            alloc_span: (e_data, alloc_end),
        },
    )
    .await?;
    Ok(data.len())
}

// ── Shared COW mini-transaction ────────────────────────────────────

/// One tree copied-on-write in a mini-transaction: its fully-edited leaf and the
/// old (freed) / new (pre-allocated) block addresses.
struct CowLeaf {
    leaf: Vec<u8>,
    old: u64,
    new: u64,
}

impl CowLeaf {
    fn new(leaf: Vec<u8>, old: u64, new: u64) -> Self {
        CowLeaf { leaf, old, new }
    }
}

/// A data extent recorded into the extent tree as an `EXTENT_ITEM` +
/// `EXTENT_DATA_REF{root, objectid, offset=0, count=1}`.
struct DataRef {
    bytenr: u64,
    len: u64,
    ref_root: u64,
    objectid: u64,
}

/// The trees a single mutation copies-on-write, plus the data-extent bookkeeping
/// the extent/free-space trees must reflect. The caller supplies the fully-edited
/// fs (and, for data changes, csum) leaves; `commit_txn` owns editing the extent,
/// free-space and root leaves, stamping every node, and flipping the superblock.
struct Txn {
    fs: CowLeaf,
    csum: Option<CowLeaf>,
    ext: CowLeaf,
    root: CowLeaf,
    fst: Option<CowLeaf>,
    /// Data extents whose `EXTENT_ITEM` is removed (bytenr, disk length).
    freed_data: Vec<(u64, u64)>,
    /// Data extents whose `EXTENT_ITEM` is added.
    new_data: Vec<DataRef>,
    /// Net change to the data block group's `used` byte count.
    data_used_delta: i64,
    /// The contiguous `[start, end)` span of freshly allocated blocks to mark
    /// used in the free-space tree.
    alloc_span: (u64, u64),
}

/// Finalize a mutation: rebuild the extent tree (free every copied tree's old
/// block + freed data extents, record the new blocks + new data extents, fix the
/// block group's `used`), maintain the free-space tree, repoint the copied trees'
/// `ROOT_ITEM`s, stamp and write every node, then flip the superblock last so the
/// old trees stay intact until the atomic switch.
async fn commit_txn<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    gen: u64,
    alloc: BumpAllocator,
    mut txn: Txn,
) -> Result<(), FsError> {
    // Every copied tree: (owner root objectid, old block, new block). The extent
    // tree frees each old block and records each new block; the root tree repoints
    // each (except the root tree itself, which the superblock names).
    let mut cowed = alloc::vec![
        (format::FS_TREE_OBJECTID, txn.fs.old, txn.fs.new),
        (format::EXTENT_TREE_OBJECTID, txn.ext.old, txn.ext.new),
        (format::ROOT_TREE_OBJECTID, txn.root.old, txn.root.new),
    ];
    if let Some(c) = &txn.csum {
        cowed.push((format::CSUM_TREE_OBJECTID, c.old, c.new));
    }
    if let Some(f) = &txn.fst {
        cowed.push((format::FREE_SPACE_TREE_OBJECTID, f.old, f.new));
    }

    // ── Extent tree: free old blocks + freed data, record new blocks + data ─
    for &(bytenr, len) in &txn.freed_data {
        if let Some(slot) = leaf_find(
            &txn.ext.leaf,
            &BtrfsKey::new(bytenr, format::EXTENT_ITEM_KEY, len),
        )? {
            leaf_delete(&mut txn.ext.leaf, slot)?;
        }
    }
    for &(_, old, _) in &cowed {
        if let Some(slot) = leaf_find(
            &txn.ext.leaf,
            &BtrfsKey::new(old, format::METADATA_ITEM_KEY, 0),
        )? {
            leaf_delete(&mut txn.ext.leaf, slot)?;
        }
    }
    for d in &txn.new_data {
        leaf_insert_sorted(
            &mut txn.ext.leaf,
            &BtrfsKey::new(d.bytenr, format::EXTENT_ITEM_KEY, d.len),
            &ext_item_data(gen, d.ref_root, d.objectid),
        )?;
    }
    for &(owner, _, new) in &cowed {
        leaf_insert_sorted(
            &mut txn.ext.leaf,
            &BtrfsKey::new(new, format::METADATA_ITEM_KEY, 0),
            &ext_item_meta(gen, owner),
        )?;
    }
    // Metadata `used` is net-zero (N blocks freed, N allocated); only the data
    // extents move the needle. Apply to the block group holding the data.
    if txn.data_used_delta != 0 {
        let data_addr = txn
            .new_data
            .first()
            .map(|d| d.bytenr)
            .or_else(|| txn.freed_data.first().map(|f| f.0))
            .ok_or(FsError::InvalidData)?;
        block_group_add_used(&mut txn.ext.leaf, data_addr, txn.data_used_delta)?;
    }
    stamp_node(&mut txn.ext.leaf, txn.ext.new, gen);

    // ── Free-space tree (extent mode): mark the new allocation used, free old ─
    if let Some(fst) = txn.fst.as_mut() {
        let (bg_start, bg_len) =
            block_group_of(&txn.ext.leaf, txn.alloc_span.0)?.ok_or(FsError::InvalidData)?;
        fst_mark_used(
            &mut fst.leaf,
            bg_start,
            bg_len,
            txn.alloc_span.0,
            txn.alloc_span.1 - txn.alloc_span.0,
        )?;
        let nodesize = vol.nodesize() as u64;
        for &(_, old, _) in &cowed {
            fst_mark_free(&mut fst.leaf, bg_start, bg_len, old, nodesize)?;
        }
        for &(bytenr, len) in &txn.freed_data {
            fst_mark_free(&mut fst.leaf, bg_start, bg_len, bytenr, len)?;
        }
        stamp_node(&mut fst.leaf, fst.new, gen);
    }

    // ── Root tree: repoint each copied tree's ROOT_ITEM (not the root tree) ─
    // ROOT_ITEM fields: generation@160, bytenr@176, level@238, generation_v2@239.
    let stamp_root_item = |ri: &mut [u8], bytenr: u64| {
        ri[160..168].copy_from_slice(&gen.to_le_bytes());
        ri[176..184].copy_from_slice(&bytenr.to_le_bytes());
        ri[238] = 0; // all target trees are single leaves (level 0)
        if ri.len() >= 247 {
            ri[239..247].copy_from_slice(&gen.to_le_bytes());
        }
    };
    for &(owner, _, new) in &cowed {
        if owner == format::ROOT_TREE_OBJECTID {
            continue;
        }
        let slot = leaf_find_by_type(&txn.root.leaf, owner, format::ROOT_ITEM_KEY)?
            .ok_or(FsError::NotFound)?;
        let mut ri = leaf_item_data(&txn.root.leaf, slot)?.to_vec();
        stamp_root_item(&mut ri, new);
        leaf_replace_inplace(&mut txn.root.leaf, slot, &ri)?;
    }
    stamp_node(&mut txn.root.leaf, txn.root.new, gen);

    // ── Stamp the caller-edited fs (and csum) leaves ───────────────
    stamp_node(&mut txn.fs.leaf, txn.fs.new, gen);
    if let Some(c) = txn.csum.as_mut() {
        stamp_node(&mut c.leaf, c.new, gen);
    }

    // ── Write every new node, then flip the superblock last ────────
    vol.write_logical(txn.fs.new, &txn.fs.leaf).await?;
    if let Some(c) = &txn.csum {
        vol.write_logical(c.new, &c.leaf).await?;
    }
    vol.write_logical(txn.ext.new, &txn.ext.leaf).await?;
    vol.write_logical(txn.root.new, &txn.root.leaf).await?;
    if let Some(f) = &txn.fst {
        vol.write_logical(f.new, &f.leaf).await?;
    }

    let mut raw = vol.read_raw_superblock().await?;
    raw[72..80].copy_from_slice(&gen.to_le_bytes()); // generation
    raw[80..88].copy_from_slice(&txn.root.new.to_le_bytes()); // root
                                                              // Keep the superblock's `bytes_used@120` in step with the block group's
                                                              // `used`: metadata is COW-replaced 1:1 (net zero), so only the data delta
                                                              // moves it. A stale value trips `btrfs check`'s "super bytes used mismatch".
    let bytes_used = (le64(&raw, 120)? as i64 + txn.data_used_delta) as u64;
    raw[120..128].copy_from_slice(&bytes_used.to_le_bytes());
    let csum = block_csum(&raw[format::CSUM_SIZE..format::SUPERBLOCK_SIZE]);
    raw[0..4].copy_from_slice(&csum.to_le_bytes());
    for b in &mut raw[4..format::CSUM_SIZE] {
        *b = 0;
    }
    vol.flush().await; // data + metadata durable before the superblock flip
    vol.write_superblock(&raw).await?;

    vol.set_alloc_floor(alloc.next());
    vol.commit_roots(txn.root.new, txn.fs.new, gen);
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

    let (fs_root, fs_level) = vol.fs_tree_root();
    let (root_tree, _) = vol.root_tree_root();
    let _ = fs_level;
    let old_fs = fs_root;
    let old_root = root_tree;
    let old_ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    let old_fst = roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID)
        .await
        .ok()
        .map(|(r, _)| r);

    let mut fs_leaf = vol.read_node(old_fs).await?;
    let ext_leaf = vol.read_node(old_ext).await?;
    let root_leaf = vol.read_node(old_root).await?;
    let fst_leaf = match old_fst {
        Some(f) => Some(vol.read_node(f).await?),
        None => None,
    };
    for leaf in [&fs_leaf, &ext_leaf, &root_leaf] {
        if level(leaf)? != 0 {
            return Err(FsError::Unsupported); // multi-level trees not supported
        }
    }
    if let Some(fl) = &fst_leaf {
        if level(fl)? != 0 {
            return Err(FsError::Unsupported);
        }
    }

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
    let high_water = extent_high_water(vol, old_ext)
        .await?
        .max(vol.alloc_floor());
    let mut alloc = BumpAllocator::new(high_water);
    let n_fs = alloc.alloc_node(vol)?;
    let n_ext = alloc.alloc_node(vol)?;
    let n_root = alloc.alloc_node(vol)?;
    let n_fst = if old_fst.is_some() {
        Some(alloc.alloc_node(vol)?)
    } else {
        None
    };
    let alloc_span = (n_fs, alloc.next());

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
            fs: CowLeaf::new(fs_leaf, old_fs, n_fs),
            csum: None,
            ext: CowLeaf::new(ext_leaf, old_ext, n_ext),
            root: CowLeaf::new(root_leaf, old_root, n_root),
            fst: fst_leaf.map(|leaf| CowLeaf::new(leaf, old_fst.unwrap(), n_fst.unwrap())),
            freed_data: Vec::new(),
            new_data: Vec::new(),
            data_used_delta: 0,
            alloc_span,
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

/// Remove the entry `name` from directory `parent_ino` (default subvolume) via a
/// COW mini-transaction, freeing the child inode when its last link goes away.
///
/// Scope (else `Unsupported`): a regular file with `nlink == 1` reached by a
/// single `INODE_REF` and a non-colliding `DIR_ITEM`. Its data extents (regular,
/// exclusively owned) and their checksums are freed. Directories (use `rmdir`),
/// hardlinked inodes, subvolume mounts, and hash collisions are rejected.
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
    let (root_tree, _) = vol.root_tree_root();
    let old_fs = fs_root;
    let old_root = root_tree;
    let old_ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    let old_fst = roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID)
        .await
        .ok()
        .map(|(r, _)| r);

    let mut fs_leaf = vol.read_node(old_fs).await?;
    let ext_leaf = vol.read_node(old_ext).await?;
    let root_leaf = vol.read_node(old_root).await?;
    let fst_leaf = match old_fst {
        Some(f) => Some(vol.read_node(f).await?),
        None => None,
    };
    for leaf in [&fs_leaf, &ext_leaf, &root_leaf] {
        if level(leaf)? != 0 {
            return Err(FsError::Unsupported);
        }
    }
    if let Some(fl) = &fst_leaf {
        if level(fl)? != 0 {
            return Err(FsError::Unsupported);
        }
    }

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

    // Load the child inode; only an unshared regular file is in scope.
    let ci_slot = leaf_find(
        &fs_leaf,
        &BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
    )?
    .ok_or(FsError::NotFound)?;
    let cinode = InodeItem::decode(leaf_item_data(&fs_leaf, ci_slot)?)?;
    if cinode.is_dir() {
        return Err(FsError::InvalidData);
    }
    if cinode.nlink != 1 {
        return Err(FsError::Unsupported); // hardlinked: ref-body editing out of scope
    }

    // The child's INODE_REF back to this dir gives the DIR_INDEX offset.
    let ref_key = BtrfsKey::new(child_ino, format::INODE_REF_KEY, parent_ino);
    let ref_slot = leaf_find(&fs_leaf, &ref_key)?.ok_or(FsError::NotFound)?;
    let (dir_index, single_ref) = inode_ref_index(leaf_item_data(&fs_leaf, ref_slot)?, name_bytes)?;
    if !single_ref {
        return Err(FsError::Unsupported);
    }

    // Gather the child's regular data extents (to free) and its EXTENT_DATA keys
    // (to delete). Inline extents and holes own no separate disk block.
    let mut freed_data: Vec<(u64, u64)> = Vec::new();
    let mut ed_offsets: Vec<u64> = Vec::new();
    {
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
    let high_water = extent_high_water(vol, old_ext)
        .await?
        .max(vol.alloc_floor());
    let mut alloc = BumpAllocator::new(high_water);
    let n_fs = alloc.alloc_node(vol)?;
    let n_ext = alloc.alloc_node(vol)?;
    let n_root = alloc.alloc_node(vol)?;
    // The csum tree is only copied when there are data checksums to remove.
    let n_csum = if freed_data.is_empty() {
        None
    } else {
        Some(alloc.alloc_node(vol)?)
    };
    let n_fst = if old_fst.is_some() {
        Some(alloc.alloc_node(vol)?)
    } else {
        None
    };
    let alloc_span = (n_fs, alloc.next());

    // Edit the csum leaf: drop each freed extent's checksum item.
    let csum = if let Some(n_csum) = n_csum {
        let old_csum = roots::find_root(vol, root_tree, format::CSUM_TREE_OBJECTID)
            .await?
            .0;
        let mut csum_leaf = vol.read_node(old_csum).await?;
        if level(&csum_leaf)? != 0 {
            return Err(FsError::Unsupported);
        }
        for &(bytenr, _) in &freed_data {
            let key = BtrfsKey::new(
                format::EXTENT_CSUM_OBJECTID,
                format::EXTENT_CSUM_KEY,
                bytenr,
            );
            if let Some(slot) = leaf_find(&csum_leaf, &key)? {
                leaf_delete(&mut csum_leaf, slot)?;
            }
        }
        Some(CowLeaf::new(csum_leaf, old_csum, n_csum))
    } else {
        None
    };

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

    // Delete every item belonging to the removed name. Re-find each key because a
    // delete shifts later slots.
    let mut to_delete = alloc::vec![
        BtrfsKey::new(
            parent_ino,
            format::DIR_ITEM_KEY,
            u64::from(name_hash(name_bytes))
        ),
        BtrfsKey::new(parent_ino, format::DIR_INDEX_KEY, dir_index),
        BtrfsKey::new(child_ino, format::INODE_REF_KEY, parent_ino),
        BtrfsKey::new(child_ino, format::INODE_ITEM_KEY, 0),
    ];
    for off in ed_offsets {
        to_delete.push(BtrfsKey::new(child_ino, format::EXTENT_DATA_KEY, off));
    }
    for key in &to_delete {
        let slot = leaf_find(&fs_leaf, key)?.ok_or(FsError::NotFound)?;
        leaf_delete(&mut fs_leaf, slot)?;
    }

    commit_txn(
        vol,
        gen,
        alloc,
        Txn {
            fs: CowLeaf::new(fs_leaf, old_fs, n_fs),
            csum,
            ext: CowLeaf::new(ext_leaf, old_ext, n_ext),
            root: CowLeaf::new(root_leaf, old_root, n_root),
            fst: fst_leaf.map(|leaf| CowLeaf::new(leaf, old_fst.unwrap(), n_fst.unwrap())),
            freed_data,
            new_data: Vec::new(),
            data_used_delta: -(freed_bytes as i64),
            alloc_span,
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
    let (root_tree, _) = vol.root_tree_root();
    let old_fs = fs_root;
    let old_root = root_tree;
    let old_ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    let old_fst = roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID)
        .await
        .ok()
        .map(|(r, _)| r);

    let mut fs_leaf = vol.read_node(old_fs).await?;
    let ext_leaf = vol.read_node(old_ext).await?;
    let root_leaf = vol.read_node(old_root).await?;
    let fst_leaf = match old_fst {
        Some(f) => Some(vol.read_node(f).await?),
        None => None,
    };
    for leaf in [&fs_leaf, &ext_leaf, &root_leaf] {
        if level(leaf)? != 0 {
            return Err(FsError::Unsupported);
        }
    }
    if let Some(fl) = &fst_leaf {
        if level(fl)? != 0 {
            return Err(FsError::Unsupported);
        }
    }

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
    let high_water = extent_high_water(vol, old_ext)
        .await?
        .max(vol.alloc_floor());
    let mut alloc = BumpAllocator::new(high_water);
    let n_fs = alloc.alloc_node(vol)?;
    let n_ext = alloc.alloc_node(vol)?;
    let n_root = alloc.alloc_node(vol)?;
    let n_fst = if old_fst.is_some() {
        Some(alloc.alloc_node(vol)?)
    } else {
        None
    };
    let alloc_span = (n_fs, alloc.next());

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
            fs: CowLeaf::new(fs_leaf, old_fs, n_fs),
            csum: None,
            ext: CowLeaf::new(ext_leaf, old_ext, n_ext),
            root: CowLeaf::new(root_leaf, old_root, n_root),
            fst: fst_leaf.map(|leaf| CowLeaf::new(leaf, old_fst.unwrap(), n_fst.unwrap())),
            freed_data: Vec::new(),
            new_data: Vec::new(),
            data_used_delta: 0,
            alloc_span,
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
    let (root_tree, _) = vol.root_tree_root();
    let old_fs = fs_root;
    let old_root = root_tree;
    let old_ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    let old_fst = roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID)
        .await
        .ok()
        .map(|(r, _)| r);

    let mut fs_leaf = vol.read_node(old_fs).await?;
    let ext_leaf = vol.read_node(old_ext).await?;
    let root_leaf = vol.read_node(old_root).await?;
    let fst_leaf = match old_fst {
        Some(f) => Some(vol.read_node(f).await?),
        None => None,
    };
    for leaf in [&fs_leaf, &ext_leaf, &root_leaf] {
        if level(leaf)? != 0 {
            return Err(FsError::Unsupported);
        }
    }
    if let Some(fl) = &fst_leaf {
        if level(fl)? != 0 {
            return Err(FsError::Unsupported);
        }
    }

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
    let high_water = extent_high_water(vol, old_ext)
        .await?
        .max(vol.alloc_floor());
    let mut alloc = BumpAllocator::new(high_water);
    let n_fs = alloc.alloc_node(vol)?;
    let n_ext = alloc.alloc_node(vol)?;
    let n_root = alloc.alloc_node(vol)?;
    // The csum tree is only copied when an overwritten file's checksums go away.
    let n_csum = if freed_data.is_empty() {
        None
    } else {
        Some(alloc.alloc_node(vol)?)
    };
    let n_fst = if old_fst.is_some() {
        Some(alloc.alloc_node(vol)?)
    } else {
        None
    };
    let alloc_span = (n_fs, alloc.next());

    // Edit the csum leaf: drop the overwritten file's data checksums.
    let csum = if let Some(n_csum) = n_csum {
        let old_csum = roots::find_root(vol, root_tree, format::CSUM_TREE_OBJECTID)
            .await?
            .0;
        let mut csum_leaf = vol.read_node(old_csum).await?;
        if level(&csum_leaf)? != 0 {
            return Err(FsError::Unsupported);
        }
        for &(bytenr, _) in &freed_data {
            let key = BtrfsKey::new(
                format::EXTENT_CSUM_OBJECTID,
                format::EXTENT_CSUM_KEY,
                bytenr,
            );
            if let Some(slot) = leaf_find(&csum_leaf, &key)? {
                leaf_delete(&mut csum_leaf, slot)?;
            }
        }
        Some(CowLeaf::new(csum_leaf, old_csum, n_csum))
    } else {
        None
    };

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
            fs: CowLeaf::new(fs_leaf, old_fs, n_fs),
            csum,
            ext: CowLeaf::new(ext_leaf, old_ext, n_ext),
            root: CowLeaf::new(root_leaf, old_root, n_root),
            fst: fst_leaf.map(|leaf| CowLeaf::new(leaf, old_fst.unwrap(), n_fst.unwrap())),
            freed_data,
            new_data: Vec::new(),
            data_used_delta: -(freed_bytes as i64),
            alloc_span,
        },
    )
    .await?;
    Ok(())
}
