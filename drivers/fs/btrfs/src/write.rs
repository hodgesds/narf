//! Copy-on-write file writes (overwrite / partial / append / grow).
//!
//! Scope: a regular, uncompressed, single-`EXTENT_DATA` file in the default
//! subvolume, on a volume whose fs/csum/root/extent (and free-space, if present)
//! trees are each a single leaf (typical of a freshly-made small image). A write
//! reads the current file, applies the new bytes at any offset (growing past EOF
//! as needed), and rewrites the whole file as one new extent, as a genuine
//! copy-on-write mini-transaction that never mutates live data or metadata in
//! place. Because these trees are single leaves, every new block is pre-allocated
//! up front, letting the extent
//! leaf record its own new block — sidestepping the self-referential allocation
//! loop that full btrfs handles with delayed refs. Per write it:
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
use crate::checksum::block_csum;
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

    // The file must be a single regular, uncompressed extent at offset 0 (so the
    // whole file is one EXTENT_DATA item we can rewrite in place).
    let extents = btree::collect_for(vol, fs_root, ino, format::EXTENT_DATA_KEY).await?;
    if extents.len() != 1 {
        return Err(FsError::Unsupported);
    }
    let (ed_key, ed_body) = &extents[0];
    if ed_key.offset != 0 || ed_body.len() < 53 {
        return Err(FsError::Unsupported);
    }
    // btrfs_file_extent_item: ram_bytes@8, compression@16, type@20,
    // disk_bytenr@21, disk_num_bytes@29, extent_offset@37, num_bytes@45.
    if ed_body[16] != 0 || ed_body[20] != format::FILE_EXTENT_REG {
        return Err(FsError::Unsupported);
    }
    if le64(ed_body, 37)? != 0 {
        return Err(FsError::Unsupported); // points mid-shared-extent: out of scope
    }

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
    let old_data = le64(ed_body, 21)?; // disk_bytenr
    let old_data_len = le64(ed_body, 29)?; // disk_num_bytes

    let mut fs_leaf = vol.read_node(old_fs).await?;
    let mut csum_leaf = vol.read_node(old_csum).await?;
    let mut root_leaf = vol.read_node(old_root).await?;
    let mut ext_leaf = vol.read_node(old_ext).await?;
    let mut fst_leaf = match old_fst {
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

    // ── 4. Build the new fs leaf (repoint EXTENT_DATA, update INODE) ─
    let mut new_ed = ed_body.clone();
    new_ed[8..16].copy_from_slice(&disk_len.to_le_bytes()); // ram_bytes
    new_ed[21..29].copy_from_slice(&e_data.to_le_bytes()); // disk_bytenr
    new_ed[29..37].copy_from_slice(&disk_len.to_le_bytes()); // disk_num_bytes
    new_ed[37..45].copy_from_slice(&0u64.to_le_bytes()); // extent_offset
    new_ed[45..53].copy_from_slice(&disk_len.to_le_bytes()); // num_bytes
    let ed_slot = leaf_find(&fs_leaf, ed_key)?.ok_or(FsError::NotFound)?;
    leaf_replace_inplace(&mut fs_leaf, ed_slot, &new_ed)?;

    let inode_slot = leaf_find(&fs_leaf, &BtrfsKey::new(ino, format::INODE_ITEM_KEY, 0))?
        .ok_or(FsError::NotFound)?;
    let mut new_inode = leaf_item_data(&fs_leaf, inode_slot)?.to_vec();
    new_inode[0..8].copy_from_slice(&gen.to_le_bytes()); // generation
    new_inode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    new_inode[16..24].copy_from_slice(&new_size.to_le_bytes()); // size
    new_inode[24..32].copy_from_slice(&disk_len.to_le_bytes()); // nbytes
    leaf_replace_inplace(&mut fs_leaf, inode_slot, &new_inode)?;
    stamp_node(&mut fs_leaf, n_fs, gen);

    // ── 5. Build the new csum leaf: drop the old extent's csums, add new ─
    // The old data extent is being freed, so its csum item must go too, else
    // `btrfs check` reports "csum exists but there is no extent record".
    let old_csum_key = BtrfsKey::new(
        format::EXTENT_CSUM_OBJECTID,
        format::EXTENT_CSUM_KEY,
        old_data,
    );
    if old_data != e_data {
        if let Some(slot) = leaf_find(&csum_leaf, &old_csum_key)? {
            leaf_delete(&mut csum_leaf, slot)?;
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
    stamp_node(&mut csum_leaf, n_csum, gen);

    // ── 6. Build the new extent leaf: free old blocks, record new ──
    let mut old_meta = alloc::vec![old_fs, old_csum, old_root, old_ext];
    if let Some(old_fst) = old_fst {
        old_meta.push(old_fst);
    }
    if let Some(slot) = leaf_find(
        &ext_leaf,
        &BtrfsKey::new(old_data, format::EXTENT_ITEM_KEY, old_data_len),
    )? {
        leaf_delete(&mut ext_leaf, slot)?;
    }
    for &m in &old_meta {
        if let Some(slot) = leaf_find(&ext_leaf, &BtrfsKey::new(m, format::METADATA_ITEM_KEY, 0))? {
            leaf_delete(&mut ext_leaf, slot)?;
        }
    }
    leaf_insert_sorted(
        &mut ext_leaf,
        &BtrfsKey::new(e_data, format::EXTENT_ITEM_KEY, disk_len),
        &ext_item_data(gen, format::FS_TREE_OBJECTID, ino),
    )?;
    let mut new_meta = alloc::vec![
        (n_fs, format::FS_TREE_OBJECTID),
        (n_csum, format::CSUM_TREE_OBJECTID),
        (n_ext, format::EXTENT_TREE_OBJECTID),
        (n_root, format::ROOT_TREE_OBJECTID),
    ];
    if let Some(n_fst) = n_fst {
        new_meta.push((n_fst, format::FREE_SPACE_TREE_OBJECTID));
    }
    for &(addr, owner) in &new_meta {
        leaf_insert_sorted(
            &mut ext_leaf,
            &BtrfsKey::new(addr, format::METADATA_ITEM_KEY, 0),
            &ext_item_meta(gen, owner),
        )?;
    }
    // Block-group `used`: metadata count is unchanged (N freed, N allocated);
    // only the data extent's size may change.
    block_group_add_used(&mut ext_leaf, e_data, disk_len as i64 - old_data_len as i64)?;
    stamp_node(&mut ext_leaf, n_ext, gen);

    // ── 6b. Build the new free-space-tree leaf (extent mode) ───────
    // Mark the whole new allocation used, and free the old blocks.
    if let Some(fst_leaf) = fst_leaf.as_mut() {
        let (bg_start, bg_len) = block_group_of(&ext_leaf, e_data)?.ok_or(FsError::InvalidData)?;
        fst_mark_used(fst_leaf, bg_start, bg_len, e_data, alloc_end - e_data)?;
        // Free the old data extent and every old metadata block.
        fst_mark_free(fst_leaf, bg_start, bg_len, old_data, old_data_len)?;
        let nodesize = vol.nodesize() as u64;
        for &m in &old_meta {
            fst_mark_free(fst_leaf, bg_start, bg_len, m, nodesize)?;
        }
        stamp_node(fst_leaf, n_fst.unwrap(), gen);
    }

    // ── 7. Build the new root leaf (repoint FS/CSUM/EXTENT ROOT_ITEMs) ─
    // ROOT_ITEM fields: generation@160, bytenr@176, level@238, generation_v2@239.
    let stamp_root_item = |ri: &mut [u8], bytenr: u64| {
        ri[160..168].copy_from_slice(&gen.to_le_bytes());
        ri[176..184].copy_from_slice(&bytenr.to_le_bytes());
        ri[238] = 0; // all target trees are single leaves (level 0)
        if ri.len() >= 247 {
            ri[239..247].copy_from_slice(&gen.to_le_bytes());
        }
    };
    let mut root_updates = alloc::vec![
        (format::FS_TREE_OBJECTID, n_fs),
        (format::CSUM_TREE_OBJECTID, n_csum),
        (format::EXTENT_TREE_OBJECTID, n_ext),
    ];
    if let Some(n_fst) = n_fst {
        root_updates.push((format::FREE_SPACE_TREE_OBJECTID, n_fst));
    }
    for &(objid, bytenr) in &root_updates {
        let slot = leaf_find_by_type(&root_leaf, objid, format::ROOT_ITEM_KEY)?
            .ok_or(FsError::NotFound)?;
        let mut ri = leaf_item_data(&root_leaf, slot)?.to_vec();
        stamp_root_item(&mut ri, bytenr);
        leaf_replace_inplace(&mut root_leaf, slot, &ri)?;
    }
    stamp_node(&mut root_leaf, n_root, gen);
    let _ = fs_level;

    // ── 8. Write all new nodes, then flip the superblock ───────────
    vol.write_logical(n_fs, &fs_leaf).await?;
    vol.write_logical(n_csum, &csum_leaf).await?;
    vol.write_logical(n_ext, &ext_leaf).await?;
    vol.write_logical(n_root, &root_leaf).await?;
    if let (Some(n_fst), Some(fst_leaf)) = (n_fst, fst_leaf.as_ref()) {
        vol.write_logical(n_fst, fst_leaf).await?;
    }

    let mut raw = vol.read_raw_superblock().await?;
    raw[72..80].copy_from_slice(&gen.to_le_bytes()); // generation
    raw[80..88].copy_from_slice(&n_root.to_le_bytes()); // root
    let csum = block_csum(&raw[format::CSUM_SIZE..format::SUPERBLOCK_SIZE]);
    raw[0..4].copy_from_slice(&csum.to_le_bytes());
    for b in &mut raw[4..format::CSUM_SIZE] {
        *b = 0;
    }
    vol.flush().await; // data + metadata durable before the superblock flip
    vol.write_superblock(&raw).await?;

    vol.set_alloc_floor(alloc.next());
    vol.commit_roots(n_root, n_fs, gen);
    Ok(data.len())
}
