//! Copy-on-write file writes (overwrite / partial / append / grow).
//!
//! Scope: a regular, uncompressed, single-`EXTENT_DATA` file in the default
//! subvolume. A write reads the current file, applies the new bytes at any
//! offset (growing past EOF as needed), and rewrites the whole file as one new
//! extent. The update is genuine COW — it never mutates live data or metadata in
//! place:
//!
//! 1. a fresh data extent is allocated (above the extent-tree high-water mark)
//!    and the new content is written there;
//! 2. its per-sector CRC32C **data checksums** are inserted into the CSUM tree
//!    (so a real Linux kernel, which verifies data csums on read, accepts it);
//! 3. the fs tree is COWed — the file's `EXTENT_DATA` is repointed/resized and
//!    its `INODE_ITEM` size/generation updated — producing a new fs-tree root,
//!    leaving the old nodes byte-for-byte intact on disk;
//! 4. the root tree is COWed so its `FS_TREE` and `CSUM` `ROOT_ITEM`s name the
//!    new roots;
//! 5. a fresh superblock (generation + 1) is written last, atomically switching
//!    the volume to the new trees.
//!
//! Remaining gap toward full `btrfs check` cleanliness: the **extent tree** and
//! **free-space tree** are not yet updated, so the new extent is not accounted
//! (and the old one not freed). A kernel can *read* the file (data csums are
//! correct), but the space bookkeeping is incomplete. Bounds: no new-chunk
//! allocation and no node splitting (a full target leaf yields `NoSpace`).

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::allocator::{extent_high_water, BumpAllocator};
use crate::btree::{
    self, internal_blockptr, internal_child_slot, leaf_item_key, leaf_item_span, leaf_lower_bound,
    level, nritems, Cursor, HEADER_SIZE,
};
use crate::checksum::block_csum;
use crate::format::{self, le64, BtrfsKey};
use crate::inode::InodeItem;
use crate::roots;
use crate::volume::BtrfsVolume;

// Header field offsets rewritten when a node is COWed.
const HDR_BYTENR: usize = 48;
const HDR_GENERATION: usize = 80;
// Internal key-ptr layout within a node's data area.
const KEY_PTR_SIZE: usize = format::DISK_KEY_SIZE + 16;

/// A root-to-leaf path: `(node_logical, node_bytes, slot)` per level.
type Path = Vec<(u64, Vec<u8>, usize)>;

/// Build the exact path to the leaf item keyed `key` (which must exist).
async fn build_path<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    key: &BtrfsKey,
) -> Result<Path, FsError> {
    let mut path: Path = Vec::new();
    let mut node_logical = root;
    for _ in 0..=8 {
        let buf = vol.read_node(node_logical).await?;
        let n = nritems(&buf)? as usize;
        if level(&buf)? == 0 {
            let slot = leaf_lower_bound(&buf, n, key)?;
            if slot >= n || leaf_item_key(&buf, slot)? != *key {
                return Err(FsError::NotFound);
            }
            path.push((node_logical, buf, slot));
            return Ok(path);
        }
        if n == 0 {
            return Err(FsError::InvalidData);
        }
        let slot = internal_child_slot(&buf, n, key)?;
        let child = internal_blockptr(&buf, slot)?;
        // Store this node (its own address + bytes + descended slot); descend.
        path.push((node_logical, buf, slot));
        node_logical = child;
    }
    Err(FsError::InvalidData)
}

/// Stamp a COWed node with a freshly-allocated address + generation + CRC32C,
/// write it out, and return its new logical address.
async fn finalize_node<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    buf: &mut [u8],
    alloc: &mut BumpAllocator,
    gen: u64,
) -> Result<u64, FsError> {
    let addr = alloc.alloc_node(vol)?;
    buf[HDR_BYTENR..HDR_BYTENR + 8].copy_from_slice(&addr.to_le_bytes());
    buf[HDR_GENERATION..HDR_GENERATION + 8].copy_from_slice(&gen.to_le_bytes());
    let csum = block_csum(&buf[format::CSUM_SIZE..]);
    buf[0..4].copy_from_slice(&csum.to_le_bytes());
    for b in &mut buf[4..format::CSUM_SIZE] {
        *b = 0;
    }
    vol.write_logical(addr, buf).await?;
    Ok(addr)
}

/// COW the tree at `root`, replacing the bodies of one or more existing items
/// (all in the same leaf, each the same size as before), and return the new
/// tree-root address.
async fn cow_replace_items<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    edits: &[(BtrfsKey, Vec<u8>)],
    alloc: &mut BumpAllocator,
    gen: u64,
) -> Result<u64, FsError> {
    let path = build_path(vol, root, &edits[0].0).await?;
    let leaf_idx = path.len() - 1;
    let mut leaf = path[leaf_idx].1.clone();

    for (key, body) in edits {
        let n = nritems(&leaf)? as usize;
        let slot = leaf_lower_bound(&leaf, n, key)?;
        if slot >= n || leaf_item_key(&leaf, slot)? != *key {
            // All edits must live in this same leaf; otherwise unsupported.
            return Err(FsError::Unsupported);
        }
        let (off, size) = leaf_item_span(&leaf, slot)?;
        if size != body.len() {
            return Err(FsError::Unsupported); // same-size replacement only
        }
        let start = HEADER_SIZE + off;
        leaf[start..start + size].copy_from_slice(body);
    }

    let mut child = finalize_node(vol, &mut leaf, alloc, gen).await?;
    // Rewrite each parent's child pointer bottom-up; the item key is unchanged
    // so the parent's separator key needs no adjustment.
    for i in (0..leaf_idx).rev() {
        let mut node = path[i].1.clone();
        let slot = path[i].2;
        let ptr = HEADER_SIZE + slot * KEY_PTR_SIZE + format::DISK_KEY_SIZE;
        node[ptr..ptr + 8].copy_from_slice(&child.to_le_bytes());
        node[ptr + 8..ptr + 16].copy_from_slice(&gen.to_le_bytes());
        child = finalize_node(vol, &mut node, alloc, gen).await?;
    }
    Ok(child)
}

/// On-disk size of one leaf item entry (key + offset + size).
const LEAF_ITEM_SIZE: usize = format::DISK_KEY_SIZE + 8;

/// Build the path to the leaf where `key` belongs (for insertion). Unlike
/// [`build_path`], the key need not already exist; the leaf entry's slot is the
/// insertion point (`lower_bound`).
async fn build_path_insert<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    key: &BtrfsKey,
) -> Result<Path, FsError> {
    let mut path: Path = Vec::new();
    let mut node_logical = root;
    for _ in 0..=8 {
        let buf = vol.read_node(node_logical).await?;
        let n = nritems(&buf)? as usize;
        if level(&buf)? == 0 {
            let slot = leaf_lower_bound(&buf, n, key)?;
            path.push((node_logical, buf, slot));
            return Ok(path);
        }
        if n == 0 {
            return Err(FsError::InvalidData);
        }
        let slot = internal_child_slot(&buf, n, key)?;
        let child = internal_blockptr(&buf, slot)?;
        path.push((node_logical, buf, slot));
        node_logical = child;
    }
    Err(FsError::InvalidData)
}

/// Insert `(key, body)` into leaf `buf` at `slot`, shifting the item array and
/// placing the body at the low end of the data area. `NoSpace` if the leaf is
/// full (node splitting is not implemented).
fn leaf_insert(buf: &mut [u8], slot: usize, key: &BtrfsKey, body: &[u8]) -> Result<(), FsError> {
    let nodesize = buf.len();
    let n = nritems(buf)? as usize;
    // Lowest data offset in use (data grows down from the end of the node).
    let mut min_off = nodesize - HEADER_SIZE;
    for i in 0..n {
        let (off, _size) = leaf_item_span(buf, i)?;
        min_off = min_off.min(off);
    }
    let items_end = HEADER_SIZE + n * LEAF_ITEM_SIZE;
    let data_start = HEADER_SIZE + min_off;
    let free = data_start
        .checked_sub(items_end)
        .ok_or(FsError::InvalidData)?;
    if free < LEAF_ITEM_SIZE + body.len() {
        return Err(FsError::NoSpace);
    }

    // Shift item entries [slot..n) right by one to open a hole at `slot`.
    let src = HEADER_SIZE + slot * LEAF_ITEM_SIZE;
    let move_len = (n - slot) * LEAF_ITEM_SIZE;
    buf.copy_within(src..src + move_len, src + LEAF_ITEM_SIZE);

    // Place the body just below the current data region.
    let new_off = min_off - body.len();
    let data_abs = HEADER_SIZE + new_off;
    buf[data_abs..data_abs + body.len()].copy_from_slice(body);

    // Write the new item entry.
    let ie = HEADER_SIZE + slot * LEAF_ITEM_SIZE;
    buf[ie..ie + 8].copy_from_slice(&key.objectid.to_le_bytes());
    buf[ie + 8] = key.item_type;
    buf[ie + 9..ie + 17].copy_from_slice(&key.offset.to_le_bytes());
    buf[ie + 17..ie + 21].copy_from_slice(&(new_off as u32).to_le_bytes());
    buf[ie + 21..ie + 25].copy_from_slice(&(body.len() as u32).to_le_bytes());

    buf[96..100].copy_from_slice(&((n + 1) as u32).to_le_bytes());
    Ok(())
}

/// COW-insert a new `(key, body)` item into the tree at `root`, returning the new
/// tree-root address. Single-leaf insert (no node split); the parent separator
/// keys are updated when the insert lands at the front of a subtree.
async fn cow_insert_item<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    key: &BtrfsKey,
    body: &[u8],
    alloc: &mut BumpAllocator,
    gen: u64,
) -> Result<u64, FsError> {
    let path = build_path_insert(vol, root, key).await?;
    let leaf_idx = path.len() - 1;
    let mut leaf = path[leaf_idx].1.clone();
    let slot = path[leaf_idx].2;
    let n = nritems(&leaf)? as usize;
    if slot < n && leaf_item_key(&leaf, slot)? == *key {
        return Err(FsError::Unsupported); // update, not insert
    }
    leaf_insert(&mut leaf, slot, key, body)?;

    let mut propagate = slot == 0;
    let new_min = leaf_item_key(&leaf, 0)?;
    let mut child = finalize_node(vol, &mut leaf, alloc, gen).await?;
    for i in (0..leaf_idx).rev() {
        let mut node = path[i].1.clone();
        let pslot = path[i].2;
        let ptr = HEADER_SIZE + pslot * KEY_PTR_SIZE;
        node[ptr + format::DISK_KEY_SIZE..ptr + format::DISK_KEY_SIZE + 8]
            .copy_from_slice(&child.to_le_bytes());
        node[ptr + format::DISK_KEY_SIZE + 8..ptr + format::DISK_KEY_SIZE + 16]
            .copy_from_slice(&gen.to_le_bytes());
        if propagate {
            node[ptr..ptr + 8].copy_from_slice(&new_min.objectid.to_le_bytes());
            node[ptr + 8] = new_min.item_type;
            node[ptr + 9..ptr + 17].copy_from_slice(&new_min.offset.to_le_bytes());
            propagate = pslot == 0;
        }
        child = finalize_node(vol, &mut node, alloc, gen).await?;
    }
    Ok(child)
}

/// Fetch the exact key and body of the sole item matching `(objectid,
/// item_type)` at or after offset 0 in the tree at `root`.
async fn find_keyed<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    objectid: u64,
    item_type: u8,
) -> Result<(BtrfsKey, Vec<u8>), FsError> {
    let start = BtrfsKey::new(objectid, item_type, 0);
    let cursor = Cursor::seek(vol, root, &start).await?;
    match cursor.current()? {
        Some((key, body)) if key.objectid == objectid && key.item_type == item_type => {
            Ok((key, body.to_vec()))
        }
        _ => Err(FsError::NotFound),
    }
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

    // ── 2. Allocate + write the new data extent ────────────────────
    let extent_tree = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    // Seed the allocator above both the extent tree's high-water mark and any
    // earlier same-session write (the extent tree doesn't yet record our
    // allocations, so successive writes would otherwise collide).
    let high_water = extent_high_water(vol, extent_tree)
        .await?
        .max(vol.alloc_floor());
    let gen = vol.superblock().generation + 1;
    let mut alloc = BumpAllocator::new(high_water);

    let new_extent = alloc.alloc_data(vol, disk_len)?;
    let mut payload = buf;
    payload.resize(disk_len as usize, 0);
    vol.write_logical(new_extent, &payload).await?;

    // ── 2b. Insert data checksums for the new extent (CSUM tree) ───
    // A real Linux kernel verifies these on every data read, so the write is
    // not interop-safe without them.
    let (csum_root, csum_level) =
        roots::find_root(vol, root_tree, format::CSUM_TREE_OBJECTID).await?;
    let csums = crate::csum::compute_csums(&payload, sectorsize as usize);
    let csum_key = BtrfsKey::new(
        format::EXTENT_CSUM_OBJECTID,
        format::EXTENT_CSUM_KEY,
        new_extent,
    );
    let new_csum_root = cow_insert_item(vol, csum_root, &csum_key, &csums, &mut alloc, gen).await?;

    // ── 3. COW the fs tree (repoint + resize EXTENT_DATA, INODE_ITEM) ─
    let mut new_ed = ed_body.clone();
    new_ed[8..16].copy_from_slice(&disk_len.to_le_bytes()); // ram_bytes
    new_ed[21..29].copy_from_slice(&new_extent.to_le_bytes()); // disk_bytenr
    new_ed[29..37].copy_from_slice(&disk_len.to_le_bytes()); // disk_num_bytes
    new_ed[37..45].copy_from_slice(&0u64.to_le_bytes()); // extent_offset
    new_ed[45..53].copy_from_slice(&disk_len.to_le_bytes()); // num_bytes

    let (inode_key, inode_body) = find_keyed(vol, fs_root, ino, format::INODE_ITEM_KEY).await?;
    let mut new_inode = inode_body.clone();
    new_inode[0..8].copy_from_slice(&gen.to_le_bytes()); // generation
    new_inode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid
    new_inode[16..24].copy_from_slice(&new_size.to_le_bytes()); // size
    new_inode[24..32].copy_from_slice(&disk_len.to_le_bytes()); // nbytes

    let new_fs_root = cow_replace_items(
        vol,
        fs_root,
        &[(*ed_key, new_ed), (inode_key, new_inode)],
        &mut alloc,
        gen,
    )
    .await?;

    // ── 4. COW the root tree: repoint the FS_TREE and CSUM ROOT_ITEMs ─
    // btrfs_root_item.bytenr@176, .level@238.
    let (fs_ri_key, fs_ri_body) = find_keyed(
        vol,
        root_tree,
        format::FS_TREE_OBJECTID,
        format::ROOT_ITEM_KEY,
    )
    .await?;
    let mut new_fs_ri = fs_ri_body.clone();
    new_fs_ri[176..184].copy_from_slice(&new_fs_root.to_le_bytes());
    new_fs_ri[238] = fs_level;

    let (cs_ri_key, cs_ri_body) = find_keyed(
        vol,
        root_tree,
        format::CSUM_TREE_OBJECTID,
        format::ROOT_ITEM_KEY,
    )
    .await?;
    let mut new_cs_ri = cs_ri_body.clone();
    new_cs_ri[176..184].copy_from_slice(&new_csum_root.to_le_bytes());
    new_cs_ri[238] = csum_level;

    let new_root_tree = cow_replace_items(
        vol,
        root_tree,
        &[(fs_ri_key, new_fs_ri), (cs_ri_key, new_cs_ri)],
        &mut alloc,
        gen,
    )
    .await?;

    // ── 4. Write the new superblock last (atomic switch) ───────────
    let mut raw = vol.read_raw_superblock().await?;
    raw[72..80].copy_from_slice(&gen.to_le_bytes()); // generation
    raw[80..88].copy_from_slice(&new_root_tree.to_le_bytes()); // root
    let csum = block_csum(&raw[format::CSUM_SIZE..format::SUPERBLOCK_SIZE]);
    raw[0..4].copy_from_slice(&csum.to_le_bytes());
    for b in &mut raw[4..format::CSUM_SIZE] {
        *b = 0;
    }
    vol.flush().await; // data + metadata durable before the superblock flip
    vol.write_superblock(&raw).await?;

    // ── 5. Publish the new roots into the live volume ──────────────
    vol.set_alloc_floor(alloc.next());
    vol.commit_roots(new_root_tree, new_fs_root, gen);
    Ok(data.len())
}
