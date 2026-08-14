//! Generic btrfs B-tree engine: node decoding, key search, ordered iteration.
//!
//! btrfs stores every object (chunks, roots, inodes, dir entries, file extents)
//! as items in copy-on-write B-trees keyed by `(objectid, type, offset)`. A node
//! is a `nodesize` block beginning with a `btrfs_header`; internal nodes hold
//! `(key, blockptr)` pairs pointing at child nodes (by logical address), leaves
//! hold `(key, offset, size)` items whose bodies live in the node's data area.
//!
//! This module provides pure decoders (unit-tested against hand-built nodes) and
//! an async [`Cursor`] that walks the tree in key order, descending through the
//! chunk map via [`BtrfsVolume::read_node`]. It is read-only; the COW write path
//! builds on the same decoders in `write.rs`.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::format::{le32, le64, BtrfsKey, DISK_KEY_SIZE};
use crate::volume::BtrfsVolume;

/// Size of `struct btrfs_header` (csum..level inclusive).
pub const HEADER_SIZE: usize = 101;
/// On-disk size of one leaf `struct btrfs_item` (key + offset + size).
const LEAF_ITEM_SIZE: usize = DISK_KEY_SIZE + 8;
/// On-disk size of one internal `struct btrfs_key_ptr` (key + blockptr + gen).
const KEY_PTR_SIZE: usize = DISK_KEY_SIZE + 16;
/// `BTRFS_MAX_LEVEL`: hard cap on tree depth, used as a descent guard.
const MAX_LEVEL: usize = 8;

// ── Header / item accessors (pure) ─────────────────────────────────

/// Number of items (leaf) or child pointers (internal) in a node.
pub fn nritems(buf: &[u8]) -> Result<u32, FsError> {
    le32(buf, 96)
}

/// Node level: 0 is a leaf, >0 an internal node.
pub fn level(buf: &[u8]) -> Result<u8, FsError> {
    buf.get(100).copied().ok_or(FsError::InvalidData)
}

/// Key of leaf item `i`.
pub fn leaf_item_key(buf: &[u8], i: usize) -> Result<BtrfsKey, FsError> {
    let off = HEADER_SIZE
        .checked_add(i.checked_mul(LEAF_ITEM_SIZE).ok_or(FsError::InvalidData)?)
        .ok_or(FsError::InvalidData)?;
    BtrfsKey::decode(buf, off)
}

/// `(data_offset, data_size)` of leaf item `i`. `data_offset` is relative to
/// the end of the header.
pub fn leaf_item_span(buf: &[u8], i: usize) -> Result<(usize, usize), FsError> {
    let base = HEADER_SIZE + i * LEAF_ITEM_SIZE;
    let off = le32(buf, base + DISK_KEY_SIZE)? as usize;
    let size = le32(buf, base + DISK_KEY_SIZE + 4)? as usize;
    Ok((off, size))
}

/// Body bytes of leaf item `i`.
pub fn leaf_item_data(buf: &[u8], i: usize) -> Result<&[u8], FsError> {
    let (off, size) = leaf_item_span(buf, i)?;
    let start = HEADER_SIZE.checked_add(off).ok_or(FsError::InvalidData)?;
    let end = start.checked_add(size).ok_or(FsError::InvalidData)?;
    buf.get(start..end).ok_or(FsError::InvalidData)
}

/// Key of internal child pointer `i`.
pub fn internal_key(buf: &[u8], i: usize) -> Result<BtrfsKey, FsError> {
    let off = HEADER_SIZE
        .checked_add(i.checked_mul(KEY_PTR_SIZE).ok_or(FsError::InvalidData)?)
        .ok_or(FsError::InvalidData)?;
    BtrfsKey::decode(buf, off)
}

/// Logical address of internal child pointer `i`.
pub fn internal_blockptr(buf: &[u8], i: usize) -> Result<u64, FsError> {
    let off = HEADER_SIZE + i * KEY_PTR_SIZE + DISK_KEY_SIZE;
    le64(buf, off)
}

/// First leaf slot whose key is `>= target` (an insertion point in `0..=n`).
pub fn leaf_lower_bound(buf: &[u8], n: usize, target: &BtrfsKey) -> Result<usize, FsError> {
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if leaf_item_key(buf, mid)? < *target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo)
}

/// Internal child slot to descend into when searching for `target`: the last
/// pointer whose key is `<= target`, clamped to slot 0.
pub fn internal_child_slot(buf: &[u8], n: usize, target: &BtrfsKey) -> Result<usize, FsError> {
    // First slot with key > target.
    let (mut lo, mut hi) = (0usize, n);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if internal_key(buf, mid)? <= *target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    Ok(lo.saturating_sub(1))
}

// ── Cursor ─────────────────────────────────────────────────────────

/// Ordered read cursor over one B-tree. Owns the node buffers along the current
/// root-to-leaf path so iteration survives across `await` points.
#[derive(Debug)]
pub struct Cursor<'v, B: BlockDevice + 'static> {
    vol: &'v BtrfsVolume<B>,
    /// `(node_buffer, slot)` from root (index 0) to the current leaf (last).
    /// Internal entries' `slot` is the descended child index; the leaf entry's
    /// `slot` is the current item index.
    path: Vec<(Vec<u8>, usize)>,
}

impl<'v, B: BlockDevice + 'static> Cursor<'v, B> {
    /// Position a cursor at the first item with key `>= target` in the tree
    /// rooted at logical `root`.
    pub async fn seek(
        vol: &'v BtrfsVolume<B>,
        root: u64,
        target: &BtrfsKey,
    ) -> Result<Cursor<'v, B>, FsError> {
        let mut path: Vec<(Vec<u8>, usize)> = Vec::new();
        let mut node_logical = root;
        for _ in 0..=MAX_LEVEL {
            let buf = vol.read_node(node_logical).await?;
            let n = nritems(&buf)? as usize;
            if level(&buf)? == 0 {
                let slot = leaf_lower_bound(&buf, n, target)?;
                path.push((buf, slot));
                let mut cursor = Cursor { vol, path };
                if slot >= n {
                    cursor.advance_to_next_leaf().await?;
                }
                return Ok(cursor);
            }
            if n == 0 {
                return Err(FsError::InvalidData);
            }
            let slot = internal_child_slot(&buf, n, target)?;
            node_logical = internal_blockptr(&buf, slot)?;
            path.push((buf, slot));
        }
        Err(FsError::InvalidData)
    }

    /// The item the cursor currently points at, or `None` if exhausted.
    pub fn current(&self) -> Result<Option<(BtrfsKey, &[u8])>, FsError> {
        let Some((buf, slot)) = self.path.last() else {
            return Ok(None);
        };
        let n = nritems(buf)? as usize;
        if *slot >= n {
            return Ok(None);
        }
        Ok(Some((
            leaf_item_key(buf, *slot)?,
            leaf_item_data(buf, *slot)?,
        )))
    }

    /// Advance to the next item in key order.
    pub async fn advance(&mut self) -> Result<(), FsError> {
        let (buf, slot) = self.path.last_mut().ok_or(FsError::InvalidData)?;
        let n = nritems(buf)? as usize;
        if *slot + 1 < n {
            *slot += 1;
            Ok(())
        } else {
            self.advance_to_next_leaf().await
        }
    }

    /// Climb to the nearest ancestor with an unvisited child subtree, then
    /// descend to its leftmost leaf. Leaves the path empty (exhausted) if none.
    async fn advance_to_next_leaf(&mut self) -> Result<(), FsError> {
        loop {
            self.path.pop();
            let idx = self.path.len();
            if idx == 0 {
                return Ok(());
            }
            let (n, slot) = {
                let (buf, slot) = &self.path[idx - 1];
                (nritems(buf)? as usize, *slot)
            };
            if slot + 1 >= n {
                continue;
            }
            let mut child = {
                let (buf, _) = &self.path[idx - 1];
                internal_blockptr(buf, slot + 1)?
            };
            self.path[idx - 1].1 = slot + 1;
            // Descend to the leftmost leaf of the sibling subtree.
            for _ in 0..=MAX_LEVEL {
                let cbuf = self.vol.read_node(child).await?;
                if level(&cbuf)? == 0 {
                    self.path.push((cbuf, 0));
                    return Ok(());
                }
                if nritems(&cbuf)? == 0 {
                    return Err(FsError::InvalidData);
                }
                let next = internal_blockptr(&cbuf, 0)?;
                self.path.push((cbuf, 0));
                child = next;
            }
            return Err(FsError::InvalidData);
        }
    }
}

// ── Convenience queries ────────────────────────────────────────────

/// Return the body of the item exactly matching `key`, or `None`.
pub async fn find_item<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    key: &BtrfsKey,
) -> Result<Option<Vec<u8>>, FsError> {
    let cursor = Cursor::seek(vol, root, key).await?;
    match cursor.current()? {
        Some((k, data)) if k == *key => Ok(Some(data.to_vec())),
        _ => Ok(None),
    }
}

/// The `(key, body)` of the greatest item whose key is strictly less than
/// `ceiling`, or `None` if the tree has no item before it. Descends to where
/// `ceiling` would sit, then — if that leaf holds nothing below it — backtracks to
/// the previous sibling subtree and takes its rightmost item. `O(log N)`; used to
/// find the highest inode number and the highest `DIR_INDEX` of a directory
/// without scanning the tree.
pub async fn last_before<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    ceiling: &BtrfsKey,
) -> Result<Option<(BtrfsKey, Vec<u8>)>, FsError> {
    // Descend, remembering each internal node and the child slot taken.
    let mut path: Vec<(Vec<u8>, usize)> = Vec::new();
    let mut node = root;
    let leaf = loop {
        let buf = vol.read_node(node).await?;
        if level(&buf)? == 0 {
            break buf;
        }
        let n = nritems(&buf)? as usize;
        if n == 0 {
            return Err(FsError::InvalidData);
        }
        let slot = internal_child_slot(&buf, n, ceiling)?;
        node = internal_blockptr(&buf, slot)?;
        path.push((buf, slot));
    };
    // The last slot in this leaf with key < ceiling, if any.
    let n = nritems(&leaf)? as usize;
    let lb = leaf_lower_bound(&leaf, n, ceiling)?; // first slot with key >= ceiling
    if lb > 0 {
        let slot = lb - 1;
        return Ok(Some((
            leaf_item_key(&leaf, slot)?,
            leaf_item_data(&leaf, slot)?.to_vec(),
        )));
    }
    // Nothing here precedes `ceiling`: drop to the previous sibling subtree and
    // take its rightmost leaf item (that whole subtree is entirely < ceiling).
    while let Some((buf, slot)) = path.pop() {
        if slot == 0 {
            continue;
        }
        let mut child = internal_blockptr(&buf, slot - 1)?;
        let last_leaf = loop {
            let cbuf = vol.read_node(child).await?;
            let cn = nritems(&cbuf)? as usize;
            if cn == 0 {
                return Err(FsError::InvalidData);
            }
            if level(&cbuf)? == 0 {
                break cbuf;
            }
            child = internal_blockptr(&cbuf, cn - 1)?;
        };
        let cn = nritems(&last_leaf)? as usize;
        return Ok(Some((
            leaf_item_key(&last_leaf, cn - 1)?,
            leaf_item_data(&last_leaf, cn - 1)?.to_vec(),
        )));
    }
    Ok(None)
}

/// Collect `(key, body)` for every item with the given `objectid` and
/// `item_type`, in key order. Used for readdir (`DIR_INDEX`) and file-extent
/// (`EXTENT_DATA`) scans.
pub async fn collect_for<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    root: u64,
    objectid: u64,
    item_type: u8,
) -> Result<Vec<(BtrfsKey, Vec<u8>)>, FsError> {
    let start = BtrfsKey::new(objectid, item_type, 0);
    let mut cursor = Cursor::seek(vol, root, &start).await?;
    let mut out = Vec::new();
    while let Some((key, data)) = cursor.current()? {
        if key.objectid != objectid || key.item_type != item_type {
            break;
        }
        out.push((key, data.to_vec()));
        cursor.advance().await?;
    }
    Ok(out)
}
