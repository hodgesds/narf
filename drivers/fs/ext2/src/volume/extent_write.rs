//! ext4 extent-tree WRITE path: allocate a block for a logical block that
//! is a hole (or inside an uninitialized extent), and free a whole tree.
//!
//! The read side (`map_block_extents`) already walked extent trees; the
//! write side answered `Unsupported` for anything that needed a new
//! mapping, which the syscall layer reports as -EINVAL. So every file an
//! ext4 volume created with `EXT4_EXTENTS_FL` — i.e. every regular file and
//! directory Linux ever made on it — could be overwritten in place but
//! never grown, truncated or unlinked on NARF. `/var/log/wtmp` is one such
//! file: glibc's `updwtmpx` appends a 384-byte record, the write failed
//! -EINVAL, and systemd-update-utmp reported "Failed to write utmp record:
//! Invalid argument".
//!
//! Linux references (`fs/ext4/extents.c`):
//! - `ext4_ext_map_blocks` — allocate for a hole; convert an unwritten
//!   extent when written (`ext4_ext_handle_unwritten_extents` ->
//!   `ext4_split_convert_extents`), which splits it into up to three.
//! - `ext4_ext_try_to_merge` / `ext4_can_extents_be_merged` — a new block
//!   physically and logically adjacent to the previous extent extends it
//!   (initialized extents only, up to `EXT_INIT_MAX_LEN`).
//! - `ext4_ext_grow_indepth` — a full in-inode root moves into a new leaf
//!   block and becomes a one-entry index.
//! - `ext4_ext_split` / `ext4_ext_create_new_leaf` — a full leaf below the
//!   root gets a sibling, indexed from the parent.
//! - `ext4_ext_remove_space` — truncate-to-zero frees every extent and
//!   every index/leaf block, and leaves an empty depth-0 root.
//! - `ext4_ext_correct_indexes` — an index key follows its child's first
//!   extent.
//!
//! LINUX-GAP: a leaf split needs room in its parent; a tree whose root
//! index is full (four leaf blocks of 340 extents each at 4 KiB) answers
//! `NoSpace` rather than growing a second index level. Allocation is goal
//! directed (next block after the previous extent) but has no mballoc
//! preallocation, so a fragmented volume produces more extents.

use alloc::vec;
use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use super::super::extent::{ExtentHeader, ExtentIndex, ExtentLeaf, EXT4_EXTENT_MAGIC};
use super::super::inode::Inode;
use super::{metadata_csum, BitmapKind, Ext2Volume};

/// `EXT_INIT_MAX_LEN`.
const EXT_INIT_MAX_LEN: u16 = 32768;
/// `EXT_UNWRITTEN_MAX_LEN`.
const EXT_UNWRITTEN_MAX_LEN: u16 = EXT_INIT_MAX_LEN - 1;
/// Root node capacity inside `i_block` (60 bytes - 12-byte header).
const ROOT_MAX: u16 = 4;

fn corrupt() -> FsError {
    FsError::Io(narf_block::BlockError::IOError)
}

pub(super) fn root_bytes(inode: &Inode) -> Vec<u8> {
    let mut out = vec![0u8; 60];
    for (i, b) in inode.block.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&b.to_le_bytes());
    }
    out
}

fn store_root(inode: &mut Inode, bytes: &[u8]) {
    for (i, slot) in inode.block.iter_mut().enumerate() {
        *slot = u32::from_le_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
}

fn write_header(out: &mut [u8], entries: u16, max: u16, depth: u16) {
    out[0..2].copy_from_slice(&EXT4_EXTENT_MAGIC.to_le_bytes());
    out[2..4].copy_from_slice(&entries.to_le_bytes());
    out[4..6].copy_from_slice(&max.to_le_bytes());
    out[6..8].copy_from_slice(&depth.to_le_bytes());
    // eh_generation is unused by ext4; keep whatever was there.
}

fn encode_leaf(out: &mut [u8], off: usize, e: &ExtentLeaf) {
    out[off..off + 4].copy_from_slice(&e.logical.to_le_bytes());
    let raw = if e.is_uninitialized {
        e.len + EXT_INIT_MAX_LEN
    } else {
        e.len
    };
    out[off + 4..off + 6].copy_from_slice(&raw.to_le_bytes());
    out[off + 6..off + 8].copy_from_slice(&((e.physical >> 32) as u16).to_le_bytes());
    out[off + 8..off + 12].copy_from_slice(&(e.physical as u32).to_le_bytes());
}

fn encode_index(out: &mut [u8], off: usize, idx: &ExtentIndex) {
    out[off..off + 4].copy_from_slice(&idx.logical.to_le_bytes());
    out[off + 4..off + 8].copy_from_slice(&(idx.leaf as u32).to_le_bytes());
    out[off + 8..off + 10].copy_from_slice(&((idx.leaf >> 32) as u16).to_le_bytes());
    out[off + 10..off + 12].copy_from_slice(&0u16.to_le_bytes());
}

/// Zero a node's entry area (everything after the 12-byte header) before it
/// is re-encoded with fewer entries, so no stale entry survives past
/// `eh_entries`. A non-root block keeps its trailing `ext4_extent_tail`,
/// which `write_extent_node` recomputes.
fn clear_entries(node: &mut [u8]) {
    let end = if node.len() > 60 {
        node.len() - 4
    } else {
        node.len()
    };
    node[12..end].iter_mut().for_each(|b| *b = 0);
}

fn decode_leaves(node: &[u8], hdr: &ExtentHeader) -> Result<Vec<ExtentLeaf>, FsError> {
    let n = hdr.entries as usize;
    if 12 + n * 12 > node.len() {
        return Err(corrupt());
    }
    (0..n)
        .map(|i| ExtentLeaf::parse(&node[12 + i * 12..24 + i * 12]).ok_or_else(corrupt))
        .collect()
}

fn decode_indexes(node: &[u8], hdr: &ExtentHeader) -> Result<Vec<ExtentIndex>, FsError> {
    let n = hdr.entries as usize;
    if 12 + n * 12 > node.len() {
        return Err(corrupt());
    }
    (0..n)
        .map(|i| ExtentIndex::parse(&node[12 + i * 12..24 + i * 12]).ok_or_else(corrupt))
        .collect()
}

/// One node on the root-to-leaf path: `block == 0` is the in-inode root.
struct PathNode {
    block: u64,
    bytes: Vec<u8>,
    /// Index (in the parent) of the entry that points here.
    slot_in_parent: usize,
}

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// Leaf entries per non-root extent block (`ext4_ext_space_block`).
    fn extent_block_max(&self) -> u16 {
        ((self.block_size() - 12) / 12) as u16
    }

    /// Write a non-root extent node with its `ext4_extent_tail` checksum.
    async fn write_extent_node(
        &self,
        inode_no: u32,
        inode: &Inode,
        block: u64,
        bytes: &mut [u8],
    ) -> Result<(), FsError> {
        let _ = metadata_csum::write_extent_block_checksum(
            &self.superblock,
            inode_no,
            inode.generation,
            bytes,
        );
        self.write_block(block, bytes).await
    }

    /// Allocate a block at or after `goal` in `goal`'s group, falling back
    /// to the first free block anywhere (`ext4_ext_find_goal` + allocator).
    pub(super) async fn alloc_block_near(&self, goal: u64) -> Result<u64, FsError> {
        let bpg = self.superblock.blocks_per_group as u64;
        let first = self.superblock.first_data_block as u64;
        if goal >= first && goal < self.superblock.total_blocks() {
            let _allocation = self.allocation_lock.lock().await;
            let group = ((goal - first) / bpg) as usize;
            if let Some(gd) = self.group_descs.get(group) {
                let group_first = first + group as u64 * bpg;
                let group_last = (group_first + bpg).min(self.superblock.total_blocks());
                let bits = (group_last - group_first) as u32;
                let start = (goal - group_first) as u32;
                if let Some(bit) = self
                    .alloc_in_bitmap_block(group, BitmapKind::Block, gd.block_bitmap, bits, start)
                    .await?
                {
                    return Ok(group_first + bit as u64);
                }
            }
        }
        self.alloc_block().await
    }

    async fn zero_block(&self, block: u64) -> Result<(), FsError> {
        let zeros = vec![0u8; self.block_size()];
        self.write_block(block, &zeros).await
    }

    /// Descend from the root to the leaf that covers (or would hold)
    /// `logical`.
    async fn extent_path(&self, inode: &Inode, logical: u32) -> Result<Vec<PathNode>, FsError> {
        let mut path = vec![PathNode {
            block: 0,
            bytes: root_bytes(inode),
            slot_in_parent: 0,
        }];
        for _ in 0..8 {
            let node = &path.last().ok_or_else(corrupt)?.bytes;
            let hdr = ExtentHeader::parse(node).ok_or_else(corrupt)?;
            if hdr.is_leaf() {
                return Ok(path);
            }
            let indexes = decode_indexes(node, &hdr)?;
            if indexes.is_empty() {
                return Err(corrupt());
            }
            // `ext4_ext_binsearch_idx`: the last index whose key <= logical,
            // or the first one when logical precedes them all.
            let slot = indexes
                .iter()
                .rposition(|idx| idx.logical <= logical)
                .unwrap_or(0);
            let mut child = vec![0u8; self.block_size()];
            self.read_block(indexes[slot].leaf, &mut child).await?;
            path.push(PathNode {
                block: indexes[slot].leaf,
                bytes: child,
                slot_in_parent: slot,
            });
        }
        Err(corrupt())
    }

    /// Store `entries` into the path's leaf, growing or splitting the tree
    /// when they no longer fit. `inode.block` / `inode.blocks` are updated
    /// in place; the caller writes the inode.
    async fn store_leaf(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        mut path: Vec<PathNode>,
        entries: Vec<ExtentLeaf>,
    ) -> Result<(), FsError> {
        let spb = (self.block_size() / 512) as u32;
        let leaf_i = path.len() - 1;
        let is_root = leaf_i == 0;
        let max = if is_root {
            ROOT_MAX
        } else {
            self.extent_block_max()
        };
        if entries.len() <= max as usize {
            let node = &mut path[leaf_i];
            write_header(&mut node.bytes, entries.len() as u16, max, 0);
            for (i, e) in entries.iter().enumerate() {
                encode_leaf(&mut node.bytes, 12 + i * 12, e);
            }
            if is_root {
                store_root(inode, &node.bytes);
            } else {
                let block = node.block;
                let mut bytes = core::mem::take(&mut node.bytes);
                self.write_extent_node(inode_no, inode, block, &mut bytes)
                    .await?;
                // `ext4_ext_correct_indexes`: the parent's key follows this
                // leaf's first extent.
                if let Some(first) = entries.first() {
                    let slot = path[leaf_i].slot_in_parent;
                    self.set_index_key(inode_no, inode, &mut path[leaf_i - 1], slot, first.logical)
                        .await?;
                }
            }
            return Ok(());
        }
        if is_root {
            // `ext4_ext_grow_indepth`: move the root's extents into a new
            // leaf block; the root becomes a one-entry index at depth 1.
            let goal = entries.first().map_or(0, |e| e.physical);
            let child = self.alloc_block_near(goal).await?;
            let mut bytes = vec![0u8; self.block_size()];
            let child_max = self.extent_block_max();
            write_header(&mut bytes, entries.len() as u16, child_max, 0);
            for (i, e) in entries.iter().enumerate() {
                encode_leaf(&mut bytes, 12 + i * 12, e);
            }
            self.write_extent_node(inode_no, inode, child, &mut bytes)
                .await?;
            inode.blocks = inode.blocks.saturating_add(spb);
            let mut root = path.remove(0).bytes;
            let key = entries.first().map_or(0, |e| e.logical);
            write_header(&mut root, 1, ROOT_MAX, 1);
            encode_index(
                &mut root,
                12,
                &ExtentIndex {
                    logical: key,
                    leaf: child,
                },
            );
            store_root(inode, &root);
            return Ok(());
        }
        // `ext4_ext_split` at the leaf: the entries past `max` move to a new
        // sibling leaf, indexed from the parent right after this one.
        let parent_i = leaf_i - 1;
        let parent_hdr = ExtentHeader::parse(&path[parent_i].bytes).ok_or_else(corrupt)?;
        let mut indexes = decode_indexes(&path[parent_i].bytes, &parent_hdr)?;
        if indexes.len() >= parent_hdr.max as usize {
            return Err(FsError::NoSpace);
        }
        let (keep, moved) = entries.split_at(max as usize);
        let goal = moved[0].physical;
        let sibling = self.alloc_block_near(goal).await?;
        let child_max = self.extent_block_max();
        let mut sib = vec![0u8; self.block_size()];
        write_header(&mut sib, moved.len() as u16, child_max, 0);
        for (i, e) in moved.iter().enumerate() {
            encode_leaf(&mut sib, 12 + i * 12, e);
        }
        self.write_extent_node(inode_no, inode, sibling, &mut sib)
            .await?;
        inode.blocks = inode.blocks.saturating_add(spb);
        {
            let node = &mut path[leaf_i];
            write_header(&mut node.bytes, keep.len() as u16, max, 0);
            for (i, e) in keep.iter().enumerate() {
                encode_leaf(&mut node.bytes, 12 + i * 12, e);
            }
            let block = node.block;
            let mut bytes = core::mem::take(&mut node.bytes);
            self.write_extent_node(inode_no, inode, block, &mut bytes)
                .await?;
        }
        let slot = path[leaf_i].slot_in_parent;
        indexes[slot].logical = keep[0].logical;
        indexes.insert(
            slot + 1,
            ExtentIndex {
                logical: moved[0].logical,
                leaf: sibling,
            },
        );
        let parent = &mut path[parent_i];
        write_header(
            &mut parent.bytes,
            indexes.len() as u16,
            parent_hdr.max,
            parent_hdr.depth,
        );
        for (i, idx) in indexes.iter().enumerate() {
            encode_index(&mut parent.bytes, 12 + i * 12, idx);
        }
        if parent_i == 0 {
            store_root(inode, &parent.bytes);
        } else {
            let block = parent.block;
            let mut bytes = core::mem::take(&mut parent.bytes);
            self.write_extent_node(inode_no, inode, block, &mut bytes)
                .await?;
        }
        Ok(())
    }

    async fn set_index_key(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        parent: &mut PathNode,
        slot: usize,
        key: u32,
    ) -> Result<(), FsError> {
        let off = 12 + slot * 12;
        if parent.bytes.len() < off + 4 {
            return Err(corrupt());
        }
        if parent.bytes[off..off + 4] == key.to_le_bytes() {
            return Ok(());
        }
        parent.bytes[off..off + 4].copy_from_slice(&key.to_le_bytes());
        if parent.block == 0 {
            store_root(inode, &parent.bytes);
            Ok(())
        } else {
            let mut bytes = parent.bytes.clone();
            self.write_extent_node(inode_no, inode, parent.block, &mut bytes)
                .await
        }
    }

    /// `ext4_ext_map_blocks(..., EXT4_GET_BLOCKS_CREATE)` for one block:
    /// the physical block now backing `logical`, allocating (zero-filled)
    /// or converting an unwritten extent as needed.
    pub(super) async fn extent_map_alloc(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        logical: u64,
    ) -> Result<u64, FsError> {
        let logical = u32::try_from(logical)
            .map_err(|_| FsError::Io(narf_block::BlockError::InvalidRange))?;
        let path = self.extent_path(inode, logical).await?;
        let leaf = &path.last().ok_or_else(corrupt)?.bytes;
        let hdr = ExtentHeader::parse(leaf).ok_or_else(corrupt)?;
        let mut entries = decode_leaves(leaf, &hdr)?;
        if let Some(i) = entries.iter().position(|e| e.covers(logical)) {
            let e = entries[i];
            let phys = e.translate(logical).ok_or_else(corrupt)?;
            if !e.is_uninitialized {
                return Ok(phys);
            }
            // Writing into an unwritten extent: split it into
            // [unwritten before][written block][unwritten after].
            let mut repl = Vec::with_capacity(3);
            if logical > e.logical {
                repl.push(ExtentLeaf {
                    logical: e.logical,
                    len: (logical - e.logical) as u16,
                    is_uninitialized: true,
                    physical: e.physical,
                });
            }
            repl.push(ExtentLeaf {
                logical,
                len: 1,
                is_uninitialized: false,
                physical: phys,
            });
            let after = (e.logical + e.len as u32) - logical - 1;
            if after > 0 {
                repl.push(ExtentLeaf {
                    logical: logical + 1,
                    len: after as u16,
                    is_uninitialized: true,
                    physical: phys + 1,
                });
            }
            entries.splice(i..=i, repl);
            // Its old contents are "unwritten": what a partial write does
            // not cover must read back as zeros.
            self.zero_block(phys).await?;
            self.store_leaf(inode_no, inode, path, entries).await?;
            return Ok(phys);
        }
        let prev = entries.iter().rposition(|e| e.logical < logical);
        let goal = prev.map_or(0, |p| {
            entries[p].physical + (logical - entries[p].logical) as u64
        });
        let block = self.alloc_block_near(goal).await?;
        self.zero_block(block).await?;
        inode.blocks = inode
            .blocks
            .saturating_add((self.block_size() / 512) as u32);
        let merges = prev.is_some_and(|p| {
            let e = &entries[p];
            !e.is_uninitialized
                && e.logical + e.len as u32 == logical
                && e.physical + e.len as u64 == block
                && e.len < EXT_INIT_MAX_LEN
        });
        match prev {
            Some(p) if merges => entries[p].len += 1,
            _ => {
                let at = prev.map_or(0, |p| p + 1);
                entries.insert(
                    at,
                    ExtentLeaf {
                        logical,
                        len: 1,
                        is_uninitialized: false,
                        physical: block,
                    },
                );
            }
        }
        self.store_leaf(inode_no, inode, path, entries).await?;
        Ok(block)
    }

    /// `ext4_alloc_file_blocks(..., EXT4_GET_BLOCKS_CREATE_UNWRIT_EXT)` for
    /// one block: map a hole at `logical` as an UNWRITTEN extent, which reads
    /// back as zeros until written, so the block needs no zeroing. A mapped
    /// block (written or not) is left alone. A new block physically and
    /// logically adjacent to an unwritten extent extends it
    /// (`ext4_can_extents_be_merged`). Returns whether a block was allocated.
    pub(super) async fn extent_prealloc(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        logical: u64,
    ) -> Result<bool, FsError> {
        let logical = u32::try_from(logical)
            .map_err(|_| FsError::Io(narf_block::BlockError::InvalidRange))?;
        let path = self.extent_path(inode, logical).await?;
        let leaf = &path.last().ok_or_else(corrupt)?.bytes;
        let hdr = ExtentHeader::parse(leaf).ok_or_else(corrupt)?;
        let mut entries = decode_leaves(leaf, &hdr)?;
        if entries.iter().any(|e| e.covers(logical)) {
            return Ok(false);
        }
        let prev = entries.iter().rposition(|e| e.logical < logical);
        let goal = prev.map_or(0, |p| {
            entries[p].physical + (logical - entries[p].logical) as u64
        });
        let block = self.alloc_block_near(goal).await?;
        inode.blocks = inode
            .blocks
            .saturating_add((self.block_size() / 512) as u32);
        let merges = prev.is_some_and(|p| {
            let e = &entries[p];
            e.is_uninitialized
                && e.logical + e.len as u32 == logical
                && e.physical + e.len as u64 == block
                && e.len < EXT_UNWRITTEN_MAX_LEN
        });
        match prev {
            Some(p) if merges => entries[p].len += 1,
            _ => {
                let at = prev.map_or(0, |p| p + 1);
                entries.insert(
                    at,
                    ExtentLeaf {
                        logical,
                        len: 1,
                        is_uninitialized: true,
                        physical: block,
                    },
                );
            }
        }
        self.store_leaf(inode_no, inode, path, entries).await?;
        Ok(true)
    }

    /// `ext4_alloc_file_blocks(..., EXT4_GET_BLOCKS_CONVERT_UNWRITTEN)` over
    /// logical `first..end`: every WRITTEN extent there becomes unwritten, so
    /// it reads back as zeros while keeping its blocks. An extent crossing an
    /// edge is split at it, and a converted piece merges with an unwritten,
    /// physically contiguous neighbour in the same leaf, so a large range
    /// does not fragment block by block. Holes are left alone (the caller
    /// preallocates them first).
    pub(super) async fn extent_convert_to_unwritten(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        first: u32,
        end: u64,
    ) -> Result<(), FsError> {
        let mut logical = u64::from(first);
        while logical < end {
            let l32 = u32::try_from(logical)
                .map_err(|_| FsError::Io(narf_block::BlockError::InvalidRange))?;
            let path = self.extent_path(inode, l32).await?;
            let leaf = &path.last().ok_or_else(corrupt)?.bytes;
            let hdr = ExtentHeader::parse(leaf).ok_or_else(corrupt)?;
            let mut entries = decode_leaves(leaf, &hdr)?;
            let Some(i) = entries.iter().position(|e| e.covers(l32)) else {
                // A hole: skip to the next extent in this leaf, if any.
                logical = entries
                    .iter()
                    .map(|e| u64::from(e.logical))
                    .find(|&s| s > logical)
                    .unwrap_or(logical + 1)
                    .min(end);
                continue;
            };
            let e = entries[i];
            let e_end = u64::from(e.logical) + u64::from(e.len);
            if e.is_uninitialized {
                logical = e_end;
                continue;
            }
            // [e.logical, mid_lo) written | [mid_lo, mid_hi) unwritten |
            // [mid_hi, e_end) written.
            let mid_lo = logical;
            let mid_hi = e_end
                .min(end)
                .min(mid_lo + u64::from(EXT_UNWRITTEN_MAX_LEN));
            let at = |l: u64| e.physical + (l - u64::from(e.logical));
            let mut repl = Vec::with_capacity(3);
            if mid_lo > u64::from(e.logical) {
                repl.push(ExtentLeaf {
                    len: (mid_lo - u64::from(e.logical)) as u16,
                    ..e
                });
            }
            let mut mid = ExtentLeaf {
                logical: mid_lo as u32,
                len: (mid_hi - mid_lo) as u16,
                is_uninitialized: true,
                physical: at(mid_lo),
            };
            let mut start = i;
            // `ext4_ext_try_to_merge` backwards into an unwritten neighbour.
            if repl.is_empty() && i > 0 {
                let prev = entries[i - 1];
                if prev.is_uninitialized
                    && prev.logical + u32::from(prev.len) == mid.logical
                    && prev.physical + u64::from(prev.len) == mid.physical
                    && u32::from(prev.len) + u32::from(mid.len) <= u32::from(EXT_UNWRITTEN_MAX_LEN)
                {
                    mid = ExtentLeaf {
                        len: prev.len + mid.len,
                        ..prev
                    };
                    start = i - 1;
                }
            }
            let mut stop = i;
            if mid_hi < e_end {
                repl.push(mid);
                repl.push(ExtentLeaf {
                    logical: mid_hi as u32,
                    len: (e_end - mid_hi) as u16,
                    is_uninitialized: false,
                    physical: at(mid_hi),
                });
            } else {
                // ...and forwards into an unwritten successor.
                if let Some(next) = entries.get(i + 1).copied() {
                    if next.is_uninitialized
                        && mid.logical + u32::from(mid.len) == next.logical
                        && mid.physical + u64::from(mid.len) == next.physical
                        && u32::from(mid.len) + u32::from(next.len)
                            <= u32::from(EXT_UNWRITTEN_MAX_LEN)
                    {
                        mid.len += next.len;
                        stop = i + 1;
                    }
                }
                repl.push(mid);
            }
            entries.splice(start..=stop, repl);
            self.store_leaf(inode_no, inode, path, entries).await?;
            logical = mid_hi;
        }
        Ok(())
    }

    /// `ext4_split_extent_at(..., EXT4_GET_BLOCKS_SPLIT_NOMERGE)`: if an
    /// extent maps both `at - 1` and `at`, make `at` the first block of an
    /// extent of its own (same state, written or not). Through `store_leaf`,
    /// which grows the tree when the leaf is full.
    pub(super) async fn extent_split_at(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        at: u32,
    ) -> Result<(), FsError> {
        if at == 0 {
            return Ok(());
        }
        let path = self.extent_path(inode, at).await?;
        let leaf = &path.last().ok_or_else(corrupt)?.bytes;
        let hdr = ExtentHeader::parse(leaf).ok_or_else(corrupt)?;
        let mut entries = decode_leaves(leaf, &hdr)?;
        let Some(i) = entries.iter().position(|e| e.logical < at && e.covers(at)) else {
            return Ok(());
        };
        let e = entries[i];
        let head = (at - e.logical) as u16;
        entries[i].len = head;
        entries.insert(
            i + 1,
            ExtentLeaf {
                logical: at,
                len: e.len - head,
                is_uninitialized: e.is_uninitialized,
                physical: e.physical + u64::from(head),
            },
        );
        self.store_leaf(inode_no, inode, path, entries).await
    }

    /// `ext4_ext_shift_extents`: move every extent starting at logical
    /// `from` or beyond by `delta` blocks (left for COLLAPSE_RANGE, right for
    /// INSERT_RANGE), index keys with them. The caller guarantees the moved
    /// extents land on no other mapping (the collapsed range was removed;
    /// an inserted range starts an extent of its own). Entry counts never
    /// change, so every node is rewritten in place.
    pub(super) async fn extent_shift(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        from: u32,
        delta: i64,
    ) -> Result<(), FsError> {
        let mut root = root_bytes(inode);
        self.extent_shift_node(inode_no, *inode, &mut root, from, delta, 0)
            .await?;
        store_root(inode, &root);
        Ok(())
    }

    fn extent_shift_node<'a>(
        &'a self,
        inode_no: u32,
        inode: Inode,
        node: &'a mut [u8],
        from: u32,
        delta: i64,
        level: usize,
    ) -> super::TreeFuture<'a, ()> {
        alloc::boxed::Box::pin(async move {
            if level > 8 {
                return Err(corrupt());
            }
            let moved = |logical: u32| -> Result<u32, FsError> {
                u32::try_from(i64::from(logical) + delta).map_err(|_| corrupt())
            };
            let hdr = ExtentHeader::parse(node).ok_or_else(corrupt)?;
            if hdr.is_leaf() {
                let mut entries = decode_leaves(node, &hdr)?;
                for e in entries.iter_mut().filter(|e| e.logical >= from) {
                    e.logical = moved(e.logical)?;
                }
                for (i, e) in entries.iter().enumerate() {
                    encode_leaf(node, 12 + i * 12, e);
                }
                return Ok(());
            }
            let mut indexes = decode_indexes(node, &hdr)?;
            for k in 0..indexes.len() {
                // A child may hold extents at `from` or beyond only if the
                // next key (its range's end) lies past `from`.
                let hi = indexes
                    .get(k + 1)
                    .map_or(u64::MAX, |n| u64::from(n.logical));
                if hi > u64::from(from) {
                    let mut child = vec![0u8; self.block_size()];
                    self.read_block(indexes[k].leaf, &mut child).await?;
                    self.extent_shift_node(inode_no, inode, &mut child, from, delta, level + 1)
                        .await?;
                    self.write_extent_node(inode_no, &inode, indexes[k].leaf, &mut child)
                        .await?;
                }
            }
            for idx in indexes.iter_mut().filter(|idx| idx.logical >= from) {
                idx.logical = moved(idx.logical)?;
            }
            for (i, idx) in indexes.iter().enumerate() {
                encode_index(node, 12 + i * 12, idx);
            }
            Ok(())
        })
    }

    /// `ext4_ext_remove_space(inode, 0, EXT_MAX_BLOCKS - 1)`: free every
    /// extent and every tree block, leave an empty depth-0 root. Returns the
    /// number of 512-byte sectors released.
    pub(super) async fn extent_free_all(&self, inode: &mut Inode) -> Result<u32, FsError> {
        let freed = self.extent_free_subtree(0, root_bytes(inode)).await?;
        let mut root = root_bytes(inode);
        root.iter_mut().for_each(|b| *b = 0);
        write_header(&mut root, 0, ROOT_MAX, 0);
        store_root(inode, &root);
        Ok(freed)
    }

    /// `ext4_ext_remove_space(inode, first, end - 1)`: free every block
    /// mapped at logical `first..end` (`end = u64::MAX` for "to the end of
    /// the file"). An extent wholly inside the range is freed, one crossing
    /// an edge is trimmed to stop there, and one spanning the whole range is
    /// split in two around it. A subtree left with no entries is freed with
    /// its node block, and an index key follows its child's first extent
    /// (`ext4_ext_correct_indexes`). A root left empty becomes an empty
    /// depth-0 leaf, as Linux leaves it. Returns the number of 512-byte
    /// sectors released; the caller writes the inode.
    pub(super) async fn extent_free_range(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        first: u32,
        end: u64,
    ) -> Result<u32, FsError> {
        if end <= u64::from(first) {
            return Ok(0);
        }
        // The one extent that can contain the whole range is split first:
        // that is the only case that ADDS an entry, and `store_leaf` grows
        // the tree for it. Everything after only removes or shortens.
        let mut freed = self
            .extent_split_around(inode_no, inode, first, end)
            .await?;
        let mut root = root_bytes(inode);
        let (entries, sub, _) = self
            .extent_trim_node(inode_no, *inode, &mut root, first, end, 0)
            .await?;
        freed = freed.saturating_add(sub);
        if entries == 0 {
            root.iter_mut().for_each(|b| *b = 0);
            write_header(&mut root, 0, ROOT_MAX, 0);
        }
        store_root(inode, &root);
        Ok(freed)
    }

    /// If one extent maps both `first - 1` and `end`, replace it with the
    /// part before `first` and the part from `end`, freeing the blocks in
    /// between. Returns the sectors released.
    async fn extent_split_around(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        first: u32,
        end: u64,
    ) -> Result<u32, FsError> {
        let Ok(end32) = u32::try_from(end) else {
            return Ok(0); // nothing maps past the 32-bit logical space
        };
        if first == 0 {
            return Ok(0);
        }
        let path = self.extent_path(inode, first).await?;
        let leaf = &path.last().ok_or_else(corrupt)?.bytes;
        let hdr = ExtentHeader::parse(leaf).ok_or_else(corrupt)?;
        let mut entries = decode_leaves(leaf, &hdr)?;
        let Some(i) = entries
            .iter()
            .position(|e| e.logical < first && u64::from(e.logical) + u64::from(e.len) > end)
        else {
            return Ok(0);
        };
        let e = entries[i];
        let spb = (self.block_size() / 512) as u32;
        let head = (first - e.logical) as u16;
        let skip = (end32 - e.logical) as u16;
        let mut freed = 0u32;
        for b in u64::from(head)..u64::from(skip) {
            self.free_block(e.physical + b).await?;
            freed = freed.saturating_add(spb);
        }
        let tail = ExtentLeaf {
            logical: end32,
            len: e.len - skip,
            is_uninitialized: e.is_uninitialized,
            physical: e.physical + u64::from(skip),
        };
        entries[i].len = head;
        entries.insert(i + 1, tail);
        self.store_leaf(inode_no, inode, path, entries).await?;
        Ok(freed)
    }

    /// Trim one node (`node`, already read) of the logical blocks in
    /// `first..end`, writing back every child it keeps. Returns the node's
    /// remaining entry count, the sectors freed beneath it, and the first
    /// logical block it still maps (for the parent's index key). The node
    /// itself is rewritten in `node`; the caller stores it. Never adds an
    /// entry: a range strictly inside one extent was split beforehand.
    fn extent_trim_node<'a>(
        &'a self,
        inode_no: u32,
        inode: Inode,
        node: &'a mut [u8],
        first: u32,
        end: u64,
        level: usize,
    ) -> super::TreeFuture<'a, (usize, u32, Option<u32>)> {
        alloc::boxed::Box::pin(async move {
            // The tree's depth is bounded by `eh_depth` (at most 5); refuse a
            // loop rather than recurse without end on a corrupt tree.
            if level > 8 {
                return Err(corrupt());
            }
            let spb = (self.block_size() / 512) as u32;
            let hdr = ExtentHeader::parse(node).ok_or_else(corrupt)?;
            let first64 = u64::from(first);
            let mut freed = 0u32;
            if hdr.is_leaf() {
                let mut kept = Vec::new();
                for mut e in decode_leaves(node, &hdr)? {
                    let start = u64::from(e.logical);
                    let stop = start + u64::from(e.len);
                    if stop <= first64 || start >= end {
                        kept.push(e);
                        continue;
                    }
                    // Blocks [lo, hi) of this extent (relative) go.
                    let lo = first64.saturating_sub(start);
                    let hi = (end.min(stop)) - start;
                    for b in lo..hi {
                        self.free_block(e.physical + b).await?;
                        freed = freed.saturating_add(spb);
                    }
                    if lo > 0 {
                        // Keeps its head (the split case was handled first,
                        // so nothing of it survives past `end`).
                        e.len = lo as u16;
                        kept.push(e);
                    } else if hi < u64::from(e.len) {
                        // Keeps its tail, which now starts at `end`.
                        e.logical += hi as u32;
                        e.physical += hi;
                        e.len -= hi as u16;
                        kept.push(e);
                    }
                }
                clear_entries(node);
                write_header(node, kept.len() as u16, hdr.max, 0);
                for (i, e) in kept.iter().enumerate() {
                    encode_leaf(node, 12 + i * 12, e);
                }
                let head = kept.first().map(|e| e.logical);
                return Ok((kept.len(), freed, head));
            }
            let indexes = decode_indexes(node, &hdr)?;
            let mut kept = Vec::new();
            for (k, mut idx) in indexes.iter().copied().enumerate() {
                // The child maps [idx.logical, next key); the last child
                // runs to the end of the logical space.
                let lo = u64::from(idx.logical);
                let hi = indexes
                    .get(k + 1)
                    .map_or(u64::MAX, |n| u64::from(n.logical));
                if hi <= first64 || lo >= end {
                    kept.push(idx);
                    continue;
                }
                let mut child = vec![0u8; self.block_size()];
                self.read_block(idx.leaf, &mut child).await?;
                if lo >= first64 && hi <= end {
                    // The whole subtree lies inside the range.
                    freed = freed.saturating_add(self.extent_free_subtree(idx.leaf, child).await?);
                    continue;
                }
                let (left, sub, head) = self
                    .extent_trim_node(inode_no, inode, &mut child, first, end, level + 1)
                    .await?;
                freed = freed.saturating_add(sub);
                if left == 0 {
                    self.free_block(idx.leaf).await?;
                    freed = freed.saturating_add(spb);
                } else {
                    self.write_extent_node(inode_no, &inode, idx.leaf, &mut child)
                        .await?;
                    if let Some(head) = head {
                        idx.logical = head;
                    }
                    kept.push(idx);
                }
            }
            clear_entries(node);
            write_header(node, kept.len() as u16, hdr.max, hdr.depth);
            for (i, idx) in kept.iter().enumerate() {
                encode_index(node, 12 + i * 12, idx);
            }
            let head = kept.first().map(|idx| idx.logical);
            Ok((kept.len(), freed, head))
        })
    }

    /// Free the subtree rooted at `block` (`0` = the in-inode root, which is
    /// not itself freed), every extent's blocks and every tree block in it.
    /// Returns the number of 512-byte sectors released.
    async fn extent_free_subtree(&self, block: u64, node: Vec<u8>) -> Result<u32, FsError> {
        let spb = (self.block_size() / 512) as u32;
        let mut freed = 0u32;
        // Depth-first over (block, bytes) nodes.
        let mut stack: Vec<(u64, Vec<u8>)> = vec![(block, node)];
        let mut budget = 1usize << 20;
        while let Some((block, node)) = stack.pop() {
            budget = budget.checked_sub(1).ok_or_else(corrupt)?;
            let hdr = ExtentHeader::parse(&node).ok_or_else(corrupt)?;
            if hdr.is_leaf() {
                for e in decode_leaves(&node, &hdr)? {
                    for b in 0..e.len as u64 {
                        self.free_block(e.physical + b).await?;
                        freed = freed.saturating_add(spb);
                    }
                }
            } else {
                for idx in decode_indexes(&node, &hdr)? {
                    let mut child = vec![0u8; self.block_size()];
                    self.read_block(idx.leaf, &mut child).await?;
                    stack.push((idx.leaf, child));
                }
            }
            if block != 0 {
                self.free_block(block).await?;
                freed = freed.saturating_add(spb);
            }
        }
        Ok(freed)
    }
}
