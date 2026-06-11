//! ext4 extent tree — re-exports the shared read decoders from
//! `drivers/fs/ext2/extent.rs` and adds the **write** path: build a
//! new extent leaf, insert it into a level-0 tree, split when full,
//! and merge adjacent extents that touch.
//!
//! Sources (post-relicense — NARF is GPL-2.0+ as of 2026-05-20):
//! - Linux `fs/ext4/extents.c::ext4_ext_find_extent` — the walker
//!   the shared `lookup_in_node` decoder mirrors.
//! - Linux `fs/ext4/extents.c::ext4_ext_insert_extent` — the
//!   insert + maybe-split algorithm this module reimplements.
//! - Linux `fs/ext4/extents.c::ext4_ext_try_to_merge` — adjacency
//!   merge.
//! - Linux `fs/ext4/ext4_extents.h::struct ext4_extent_header`,
//!   `struct ext4_extent`, `struct ext4_extent_idx`.

extern crate alloc;

pub use narf_drivers_fs_ext2::extent::{
    iter_leaf_extents, lookup_in_node, ExtentHeader, ExtentIndex, ExtentLeaf, LookupOutcome,
    EXT4_EXTENT_MAGIC,
};

use alloc::vec::Vec;

/// Result of an insert into the extent tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The new extent was placed into the existing node — `bytes` is
    /// the updated 60-byte i_block (or block-sized node) ready to
    /// write back.
    Placed(Vec<u8>),
    /// The new extent extends an adjacent existing one. `bytes` is
    /// the updated node; the merge means the entry count did not
    /// grow.
    Merged(Vec<u8>),
    /// The node was already at capacity. Caller must allocate a
    /// child block, push the existing entries into it, and turn the
    /// root into a depth-1 index node pointing to the child. The
    /// returned vector is the **new child leaf** populated with the
    /// existing entries plus the requested insert. Caller updates
    /// the parent (the root) to become a single-entry index node
    /// pointing at the child's physical block.
    Split {
        child_leaf_bytes: Vec<u8>,
        new_root_index_bytes: Vec<u8>,
    },
    /// The proposed extent overlaps an existing one. Refuse rather
    /// than silently overwrite.
    Overlap,
    /// Buffer too small / header malformed.
    Corrupt,
}

/// Pack a 12-byte extent leaf into `out` at offset `off`. Mirrors
/// the on-disk layout in `ext4_extent_header`'s leaf arm.
fn write_leaf(out: &mut [u8], off: usize, leaf: ExtentLeaf) {
    out[off..off + 4].copy_from_slice(&leaf.logical.to_le_bytes());
    let raw_len = if leaf.is_uninitialized {
        leaf.len | 0x8000
    } else {
        leaf.len
    };
    out[off + 4..off + 6].copy_from_slice(&raw_len.to_le_bytes());
    let phys_hi = (leaf.physical >> 32) as u16;
    let phys_lo = leaf.physical as u32;
    out[off + 6..off + 8].copy_from_slice(&phys_hi.to_le_bytes());
    out[off + 8..off + 12].copy_from_slice(&phys_lo.to_le_bytes());
}

/// Pack a 12-byte index entry into `out` at offset `off`.
fn write_index(out: &mut [u8], off: usize, idx: ExtentIndex) {
    out[off..off + 4].copy_from_slice(&idx.logical.to_le_bytes());
    let leaf_lo = idx.leaf as u32;
    let leaf_hi = (idx.leaf >> 32) as u16;
    out[off + 4..off + 8].copy_from_slice(&leaf_lo.to_le_bytes());
    out[off + 8..off + 10].copy_from_slice(&leaf_hi.to_le_bytes());
    out[off + 10..off + 12].copy_from_slice(&0u16.to_le_bytes());
}

/// Encode the 12-byte extent header at `out[0..12]`.
fn write_header(out: &mut [u8], header: ExtentHeader) {
    out[0..2].copy_from_slice(&header.magic.to_le_bytes());
    out[2..4].copy_from_slice(&header.entries.to_le_bytes());
    out[4..6].copy_from_slice(&header.max.to_le_bytes());
    out[6..8].copy_from_slice(&header.depth.to_le_bytes());
    out[8..12].copy_from_slice(&header.generation.to_le_bytes());
}

/// Insert `new_extent` into the extent tree rooted at `node_bytes`.
///
/// This implements the leaf-level case: caller's `node_bytes` is a
/// leaf (depth == 0) and the new extent is to be placed in
/// ascending-logical order, merging with any adjacent extent that
/// is contiguous in both logical AND physical space (matching
/// `fs/ext4/extents.c::ext4_can_extents_be_merged`).
///
/// Index-level inserts are decomposed by the caller: the walker
/// descends to the right leaf, calls this function, and propagates
/// `Split` upward by allocating a child block and turning the
/// parent into an index node pointing at the child.
///
/// `child_block_size` is the byte size of a freshly-allocated FS
/// block the caller will use for the split child node — typically
/// the volume's `s_log_block_size`-derived block size (e.g. 4096).
/// Only consulted on the Split path; the Placed / Merged paths
/// operate in place inside `node_bytes`.
///
/// Linux `fs/ext4/extents.c::ext4_ext_insert_extent`.
pub fn insert_into_leaf(
    node_bytes: &[u8],
    new_extent: ExtentLeaf,
    fresh_child_block: u64,
    child_block_size: usize,
) -> InsertOutcome {
    let header = match ExtentHeader::parse(node_bytes) {
        Some(h) => h,
        None => return InsertOutcome::Corrupt,
    };
    if !header.is_leaf() {
        return InsertOutcome::Corrupt;
    }
    let entries = header.entries as usize;
    let max = header.max as usize;
    if entries * 12 + 12 > node_bytes.len() {
        return InsertOutcome::Corrupt;
    }
    // Decode all existing leaf entries.
    let mut existing: Vec<ExtentLeaf> = Vec::with_capacity(entries);
    for i in 0..entries {
        let off = 12 + i * 12;
        match ExtentLeaf::parse(&node_bytes[off..off + 12]) {
            Some(l) => existing.push(l),
            None => return InsertOutcome::Corrupt,
        }
    }

    // Overlap check.
    let new_end = new_extent.logical as u64 + new_extent.len as u64;
    for l in &existing {
        let lstart = l.logical as u64;
        let lend = lstart + l.len as u64;
        if new_extent.logical as u64 >= lend || new_end <= lstart {
            continue;
        }
        return InsertOutcome::Overlap;
    }

    // Try-merge with adjacent extent (must be logical-contiguous AND
    // physical-contiguous AND same uninit state).
    // Linux `ext4_can_extents_be_merged`.
    for l in existing.iter_mut() {
        if l.is_uninitialized == new_extent.is_uninitialized
            && l.logical + l.len as u32 == new_extent.logical
            && l.physical + l.len as u64 == new_extent.physical
            && (l.len as u32 + new_extent.len as u32) <= 0x7FFF
        {
            l.len += new_extent.len;
            let mut out = node_bytes.to_vec();
            write_header(
                &mut out,
                ExtentHeader {
                    magic: header.magic,
                    entries: header.entries,
                    max: header.max,
                    depth: 0,
                    generation: header.generation,
                },
            );
            // Re-pack the merged + unchanged entries.
            for (i, e) in existing.iter().enumerate() {
                write_leaf(&mut out, 12 + i * 12, *e);
            }
            return InsertOutcome::Merged(out);
        }
        // Try merging the new extent into the LEFT of an existing one
        // (the inserted extent precedes the existing one + meets it).
        if l.is_uninitialized == new_extent.is_uninitialized
            && new_extent.logical + new_extent.len as u32 == l.logical
            && new_extent.physical + new_extent.len as u64 == l.physical
            && (l.len as u32 + new_extent.len as u32) <= 0x7FFF
        {
            l.logical = new_extent.logical;
            l.physical = new_extent.physical;
            l.len += new_extent.len;
            let mut out = node_bytes.to_vec();
            write_header(
                &mut out,
                ExtentHeader {
                    magic: header.magic,
                    entries: header.entries,
                    max: header.max,
                    depth: 0,
                    generation: header.generation,
                },
            );
            for (i, e) in existing.iter().enumerate() {
                write_leaf(&mut out, 12 + i * 12, *e);
            }
            return InsertOutcome::Merged(out);
        }
    }

    if entries < max {
        // Insert in-place, maintaining logical-block ascending order.
        let mut new_set = existing.clone();
        // Find sorted position.
        let pos = new_set
            .iter()
            .position(|e| e.logical > new_extent.logical)
            .unwrap_or(new_set.len());
        new_set.insert(pos, new_extent);
        let mut out = node_bytes.to_vec();
        write_header(
            &mut out,
            ExtentHeader {
                magic: header.magic,
                entries: header.entries + 1,
                max: header.max,
                depth: 0,
                generation: header.generation,
            },
        );
        for (i, e) in new_set.iter().enumerate() {
            write_leaf(&mut out, 12 + i * 12, *e);
        }
        return InsertOutcome::Placed(out);
    }

    // Capacity full — caller must split. We build the new child
    // node (a level-0 leaf carrying the existing entries plus the
    // new one) and the new root (a level-1 index node pointing at
    // `fresh_child_block`). The child is the same byte size as
    // the original node so it fits in the caller's allocated
    // filesystem block; we only fill the header + entries.
    //
    // Linux `fs/ext4/extents.c::ext4_ext_split` — splits one node
    // into one or more child nodes, propagating an index entry
    // upward to the parent. The single-level case is what we
    // implement here.
    let mut combined = existing.clone();
    let pos = combined
        .iter()
        .position(|e| e.logical > new_extent.logical)
        .unwrap_or(combined.len());
    combined.insert(pos, new_extent);

    // Child node lives in a freshly-allocated full FS block (the
    // i_block area is far too small to hold a 4+ entry leaf node).
    // Fall back to a reasonable default if caller passed 0.
    let child_size = if child_block_size >= 24 {
        child_block_size
    } else {
        4096
    };
    let mut child_buf = alloc::vec![0u8; child_size];
    write_header(
        &mut child_buf,
        ExtentHeader {
            magic: EXT4_EXTENT_MAGIC,
            entries: combined.len() as u16,
            max: ((child_size - 12) / 12) as u16,
            depth: 0,
            generation: header.generation,
        },
    );
    for (i, e) in combined.iter().enumerate() {
        write_leaf(&mut child_buf, 12 + i * 12, *e);
    }

    // New root — depth 1, one index entry pointing at the child.
    // We reuse the original `node_bytes.len()` so the i_block-sized
    // root fits back into the inode's i_block region.
    let root_size = node_bytes.len();
    let mut root_buf = alloc::vec![0u8; root_size];
    write_header(
        &mut root_buf,
        ExtentHeader {
            magic: EXT4_EXTENT_MAGIC,
            entries: 1,
            max: ((root_size - 12) / 12) as u16,
            depth: 1,
            generation: header.generation,
        },
    );
    let idx = ExtentIndex {
        logical: combined[0].logical,
        leaf: fresh_child_block,
    };
    write_index(&mut root_buf, 12, idx);

    InsertOutcome::Split {
        child_leaf_bytes: child_buf,
        new_root_index_bytes: root_buf,
    }
}

/// Build a freshly-empty leaf-extent node (i_block-shaped buffer:
/// 60 bytes ⇒ 12-byte header + capacity 4). Used by the
/// write path to bootstrap a new file's extent tree.
pub fn empty_iblock_leaf() -> [u8; 60] {
    let mut out = [0u8; 60];
    write_header(
        &mut out,
        ExtentHeader {
            magic: EXT4_EXTENT_MAGIC,
            entries: 0,
            max: 4,
            depth: 0,
            generation: 0,
        },
    );
    out
}

/// Helper: walk the extent tree top-down, supplying child-node
/// fetches via callback, until we land at the leaf entry covering
/// `logical_block`. Returns the physical block (with sparse-hole
/// detection) or None.
///
/// Mirrors `fs/ext4/extents.c::ext4_ext_find_extent`.
pub fn find_physical_for_logical(
    root_bytes: &[u8],
    logical_block: u32,
    mut fetch_block: impl FnMut(u64) -> Option<Vec<u8>>,
) -> Option<u64> {
    let mut buf: Vec<u8> = root_bytes.to_vec();
    // Depth-limit so a corrupt tree can't put us in an infinite descend.
    for _ in 0..6 {
        match lookup_in_node(&buf, logical_block) {
            LookupOutcome::Mapped {
                physical,
                is_uninitialized,
            } => {
                if is_uninitialized {
                    // Uninitialized extent — Linux returns zero data.
                    // Caller treats `0` as "read zeros for this block".
                    return Some(physical);
                }
                return Some(physical);
            }
            LookupOutcome::Hole => return None,
            LookupOutcome::Corrupt => return None,
            LookupOutcome::DeeperLookupRequired { child_block } => {
                buf = fetch_block(child_block)?;
            }
        }
    }
    None
}
