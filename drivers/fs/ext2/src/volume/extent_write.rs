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

    /// `ext4_ext_remove_space(inode, first, EXT_MAX_BLOCKS - 1)`: free every
    /// block mapped at logical `first` or beyond. An extent past the cut is
    /// freed, one straddling it is trimmed to end there, and a subtree left
    /// with no entries is freed with its node block. A root left empty
    /// becomes an empty depth-0 leaf, as Linux leaves it. Returns the number
    /// of 512-byte sectors released; the caller writes the inode.
    pub(super) async fn extent_free_from(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        first: u32,
    ) -> Result<u32, FsError> {
        let mut root = root_bytes(inode);
        let (entries, freed) = self
            .extent_trim_node(inode_no, *inode, &mut root, first, 0)
            .await?;
        if entries == 0 {
            root.iter_mut().for_each(|b| *b = 0);
            write_header(&mut root, 0, ROOT_MAX, 0);
        }
        store_root(inode, &root);
        Ok(freed)
    }

    /// Trim one node (`node`, already read) to the logical blocks below
    /// `first`, writing back every child it keeps. Returns the node's
    /// remaining entry count and the sectors freed beneath it. The node
    /// itself is rewritten in `node`; the caller stores it.
    fn extent_trim_node<'a>(
        &'a self,
        inode_no: u32,
        inode: Inode,
        node: &'a mut [u8],
        first: u32,
        level: usize,
    ) -> super::TreeFuture<'a, (usize, u32)> {
        alloc::boxed::Box::pin(async move {
            // The tree's depth is bounded by `eh_depth` (at most 5); refuse a
            // loop rather than recurse without end on a corrupt tree.
            if level > 8 {
                return Err(corrupt());
            }
            let spb = (self.block_size() / 512) as u32;
            let hdr = ExtentHeader::parse(node).ok_or_else(corrupt)?;
            let mut freed = 0u32;
            if hdr.is_leaf() {
                let mut kept = Vec::new();
                for mut e in decode_leaves(node, &hdr)? {
                    let start = e.logical;
                    let end = u64::from(start) + u64::from(e.len);
                    if start >= first {
                        for b in 0..u64::from(e.len) {
                            self.free_block(e.physical + b).await?;
                            freed = freed.saturating_add(spb);
                        }
                    } else if end > u64::from(first) {
                        let keep = (first - start) as u16;
                        for b in u64::from(keep)..u64::from(e.len) {
                            self.free_block(e.physical + b).await?;
                            freed = freed.saturating_add(spb);
                        }
                        e.len = keep;
                        kept.push(e);
                    } else {
                        kept.push(e);
                    }
                }
                clear_entries(node);
                write_header(node, kept.len() as u16, hdr.max, 0);
                for (i, e) in kept.iter().enumerate() {
                    encode_leaf(node, 12 + i * 12, e);
                }
                return Ok((kept.len(), freed));
            }
            let mut kept = Vec::new();
            for idx in decode_indexes(node, &hdr)? {
                let mut child = vec![0u8; self.block_size()];
                self.read_block(idx.leaf, &mut child).await?;
                if idx.logical >= first {
                    // The whole subtree lies past the cut.
                    freed = freed.saturating_add(self.extent_free_subtree(idx.leaf, child).await?);
                    continue;
                }
                let (left, sub) = self
                    .extent_trim_node(inode_no, inode, &mut child, first, level + 1)
                    .await?;
                freed = freed.saturating_add(sub);
                if left == 0 {
                    self.free_block(idx.leaf).await?;
                    freed = freed.saturating_add(spb);
                } else {
                    self.write_extent_node(inode_no, &inode, idx.leaf, &mut child)
                        .await?;
                    kept.push(idx);
                }
            }
            clear_entries(node);
            write_header(node, kept.len() as u16, hdr.max, hdr.depth);
            for (i, idx) in kept.iter().enumerate() {
                encode_index(node, 12 + i * 12, idx);
            }
            Ok((kept.len(), freed))
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
