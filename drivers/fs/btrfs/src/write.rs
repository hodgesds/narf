//! Basic copy-on-write file overwrite.
//!
//! Scope (everything else fails loudly): a **full** overwrite of an existing,
//! uncompressed, single-regular-extent file whose size does not change. The
//! write is genuine COW — it never mutates live data or metadata in place:
//!
//! 1. a fresh data extent is allocated (above the extent-tree high-water mark)
//!    and the new bytes are written there;
//! 2. the fs tree is COWed — the file's `EXTENT_DATA` is repointed at the new
//!    extent and its `INODE_ITEM` generation bumped — producing a new fs-tree
//!    root, leaving the old nodes byte-for-byte intact on disk;
//! 3. the root tree is COWed so its `FS_TREE` `ROOT_ITEM` names the new fs root;
//! 4. a fresh superblock (generation + 1) is written last, atomically switching
//!    the volume to the new trees.
//!
//! Documented limitations of this "basic" path: no new-chunk allocation (a full
//! chunk yields `NoSpace`); the extent and csum trees are **not** updated, so
//! the new extent is unaccounted and carries no data checksum. That is
//! sufficient for this driver to remount the image and read the new data back
//! (NARF does not verify data checksums), and it preserves btrfs's core COW
//! invariant (old trees intact until the superblock flips), but it is not
//! written for interop with a live Linux kernel that verifies data csums.

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

/// Fully overwrite file `ino` (current inode `inode`) with `data` via COW.
pub async fn cow_overwrite_file<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    ino: u64,
    inode: &InodeItem,
    data: &[u8],
) -> Result<usize, FsError> {
    // ── Preconditions ──────────────────────────────────────────────
    if !inode.is_regular() {
        return Err(FsError::Unsupported);
    }
    if data.len() as u64 != inode.size {
        // Only a same-size full overwrite is supported (no grow/shrink).
        return Err(FsError::Unsupported);
    }
    let (fs_root, fs_level) = vol.fs_tree_root();
    let (root_tree, _root_level) = vol.root_tree_root();

    // The file must be a single regular, uncompressed extent at offset 0.
    let extents = btree::collect_for(vol, fs_root, ino, format::EXTENT_DATA_KEY).await?;
    if extents.len() != 1 {
        return Err(FsError::Unsupported);
    }
    let (ed_key, ed_body) = &extents[0];
    if ed_key.offset != 0 || ed_body.len() < 53 {
        return Err(FsError::Unsupported);
    }
    // btrfs_file_extent_item: compression@16, type@20, disk_bytenr@21,
    // disk_num_bytes@29, extent_offset@37.
    if ed_body[16] != 0 || ed_body[20] != format::FILE_EXTENT_REG {
        return Err(FsError::Unsupported);
    }
    if le64(ed_body, 37)? != 0 {
        return Err(FsError::Unsupported); // points mid-shared-extent: out of scope
    }
    let disk_num_bytes = le64(ed_body, 29)?;

    // ── 1. Allocate + write the new data extent ────────────────────
    let extent_tree = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    let high_water = extent_high_water(vol, extent_tree).await?;
    let gen = vol.superblock().generation + 1;
    let mut alloc = BumpAllocator::new(high_water);

    let new_extent = alloc.alloc_data(vol, disk_num_bytes)?;
    let mut payload = data.to_vec();
    payload.resize(disk_num_bytes as usize, 0);
    vol.write_logical(new_extent, &payload).await?;

    // ── 2. COW the fs tree (repoint EXTENT_DATA, bump INODE_ITEM) ───
    let mut new_ed = ed_body.clone();
    new_ed[21..29].copy_from_slice(&new_extent.to_le_bytes()); // disk_bytenr
    new_ed[37..45].copy_from_slice(&0u64.to_le_bytes()); // extent_offset

    let (inode_key, inode_body) = find_keyed(vol, fs_root, ino, format::INODE_ITEM_KEY).await?;
    let mut new_inode = inode_body.clone();
    new_inode[0..8].copy_from_slice(&gen.to_le_bytes()); // generation
    new_inode[8..16].copy_from_slice(&gen.to_le_bytes()); // transid

    let new_fs_root = cow_replace_items(
        vol,
        fs_root,
        &[(*ed_key, new_ed), (inode_key, new_inode)],
        &mut alloc,
        gen,
    )
    .await?;

    // ── 3. COW the root tree (FS_TREE ROOT_ITEM -> new fs root) ─────
    let (ri_key, ri_body) = find_keyed(
        vol,
        root_tree,
        format::FS_TREE_OBJECTID,
        format::ROOT_ITEM_KEY,
    )
    .await?;
    let mut new_ri = ri_body.clone();
    // btrfs_root_item.bytenr@176, .level@238.
    new_ri[176..184].copy_from_slice(&new_fs_root.to_le_bytes());
    new_ri[238] = fs_level;
    let new_root_tree =
        cow_replace_items(vol, root_tree, &[(ri_key, new_ri)], &mut alloc, gen).await?;

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
    vol.commit_roots(new_root_tree, new_fs_root, gen);
    Ok(data.len())
}
