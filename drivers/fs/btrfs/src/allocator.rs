//! Space allocator for the COW write path.
//!
//! When the volume has a **free-space tree** (`space_cache=v2`), the allocator
//! *reclaims* space: it carves new data extents / tree nodes from the tree's
//! `FREE_SPACE_EXTENT` ranges, read once at the start of each mutation, so blocks
//! freed by earlier transactions are reused. Blocks freed by the **current**
//! transaction are not yet in the tree (the transaction returns them only on
//! commit), so they stay unavailable until it lands — preserving the COW
//! invariant that old data is untouched until the superblock flips.
//!
//! Without a free-space tree it falls back to appending strictly **above** the
//! extent tree's high-water mark (freed space is not reused). Either way, running
//! out of space surfaces as `NoSpace`, which lets the caller grow the filesystem
//! and retry.

use alloc::vec::Vec;

use narf_block::BlockDevice;
use narf_filesystem::FsError;

use crate::block_group;
use crate::btree::Cursor;
use crate::format::{self, BtrfsKey};
use crate::roots;
use crate::volume::BtrfsVolume;

/// Round `x` up to a multiple of `align` (a power of two).
fn align_up(x: u64, align: u64) -> u64 {
    (x + (align - 1)) & !(align - 1)
}

/// Highest byte end recorded in the extent tree (`bytenr + length` over all
/// `EXTENT_ITEM` / `METADATA_ITEM` items).
pub async fn extent_high_water<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    extent_tree: u64,
) -> Result<u64, FsError> {
    let nodesize = vol.nodesize() as u64;
    let mut cursor = Cursor::seek(vol, extent_tree, &BtrfsKey::new(0, 0, 0)).await?;
    let mut high = 0u64;
    while let Some((key, _)) = cursor.current()? {
        let end = match key.item_type {
            format::EXTENT_ITEM_KEY => key.objectid.saturating_add(key.offset),
            format::METADATA_ITEM_KEY => key.objectid.saturating_add(nodesize),
            _ => 0,
        };
        high = high.max(end);
        cursor.advance().await?;
    }
    if high == 0 {
        return Err(FsError::InvalidData);
    }
    Ok(high)
}

/// Read the free-space tree's free `(start, len)` ranges, from both the
/// `FREE_SPACE_EXTENT` items of extent-mode block groups and the
/// `FREE_SPACE_BITMAP` items of bitmap-mode ones (a set bit = one free sector).
/// Bitmap runs are emitted per bitmap item (not coalesced across bitmap
/// boundaries), which never merges across a block-group boundary.
async fn read_free_extents<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fst_root: u64,
) -> Result<Vec<(u64, u64)>, FsError> {
    let ss = u64::from(vol.sectorsize());
    let mut cursor = Cursor::seek(vol, fst_root, &BtrfsKey::new(0, 0, 0)).await?;
    let mut out = Vec::new();
    while let Some((key, body)) = cursor.current()? {
        match key.item_type {
            format::FREE_SPACE_EXTENT_KEY => out.push((key.objectid, key.offset)),
            format::FREE_SPACE_BITMAP_KEY => {
                // Emit a range for each maximal run of set (free) bits.
                let nbits = (key.offset / ss) as usize;
                let mut run_start: Option<u64> = None;
                for bit in 0..nbits {
                    let free = body
                        .get(bit / 8)
                        .is_some_and(|b| b & (1u8 << (bit % 8)) != 0);
                    match (free, run_start) {
                        (true, None) => run_start = Some(key.objectid + bit as u64 * ss),
                        (false, Some(s)) => {
                            out.push((s, key.objectid + bit as u64 * ss - s));
                            run_start = None;
                        }
                        _ => {}
                    }
                }
                if let Some(s) = run_start {
                    out.push((s, key.objectid + nbits as u64 * ss - s));
                }
            }
            _ => {}
        }
        cursor.advance().await?;
    }
    Ok(out)
}

/// Logical `(start, len, flags)` of every block group, read from the
/// `BLOCK_GROUP_ITEM`s in `bg_tree` (the extent tree, or the block-group tree on
/// a `BLOCK_GROUP_TREE` filesystem).
async fn read_block_group_types<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    bg_tree: u64,
) -> Result<Vec<(u64, u64, u64)>, FsError> {
    // BLOCK_GROUP_ITEM: used@0, chunk_objectid@8, flags@16.
    let mut out = Vec::new();
    for (start, len, body) in block_group::read_block_groups(vol, bg_tree).await? {
        out.push((start, len, format::le64(&body, 16)?));
    }
    Ok(out)
}

/// What an allocation is for: it must come from a block group of that type.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Kind {
    Data,
    Metadata,
}

impl Kind {
    fn accepts(self, flags: u64) -> bool {
        // A system block group is reserved for the chunk tree (it must stay
        // reachable via `sys_chunk_array` at mount): never general space.
        if flags & format::BLOCK_GROUP_SYSTEM != 0 {
            return false;
        }
        match self {
            Kind::Data => flags & format::BLOCK_GROUP_DATA != 0,
            Kind::Metadata => flags & format::BLOCK_GROUP_METADATA != 0,
        }
    }
}

/// Remove every pinned byte from `free`, splitting a free range that a pinned
/// range falls inside.
///
/// Both inputs may overlap arbitrarily; the result is sorted and disjoint over
/// whatever survives. Pinned ranges are few (one transaction's frees) and free
/// ranges are already sorted, so the quadratic shape is bounded by the pinned
/// count, not by the size of the filesystem.
pub(crate) fn subtract_pinned(free: Vec<(u64, u64)>, pinned: &[(u64, u64)]) -> Vec<(u64, u64)> {
    if pinned.is_empty() {
        return free;
    }
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(free.len());
    for (fs_start, fs_len) in free {
        // Fragments of this free range still available after every pin.
        let mut parts = alloc::vec![(fs_start, fs_start.saturating_add(fs_len))];
        for &(ps, plen) in pinned {
            let (pstart, pend) = (ps, ps.saturating_add(plen));
            let mut next = Vec::with_capacity(parts.len() + 1);
            for (start, end) in parts {
                if pend <= start || pstart >= end {
                    next.push((start, end)); // disjoint
                    continue;
                }
                if start < pstart {
                    next.push((start, pstart)); // head survives
                }
                if pend < end {
                    next.push((pend, end)); // tail survives
                }
            }
            parts = next;
            if parts.is_empty() {
                break;
            }
        }
        out.extend(parts.into_iter().map(|(s, e)| (s, e - s)));
    }
    out.sort_unstable();
    out
}

/// A single mutation's space allocator: reclaiming from the free-space tree, or
/// appending past the extent-tree high-water when there is none.
#[derive(Clone, Debug)]
pub enum Allocator {
    /// Carve from the free-space tree's free extents `(start, len, block-group
    /// flags)` (sorted by start). Reused space comes first, so the tail free
    /// run is consumed only when needed. Data extents come only from DATA
    /// block groups and tree nodes only from METADATA ones (a mixed group is
    /// both): `btrfs check` reports any other placement as "type mismatch
    /// with chunk", and Linux would misaccount it.
    Reclaim { ranges: Vec<(u64, u64, u64)> },
    /// Append past the extent-tree high-water (no free-space tree present).
    Bump { next: u64 },
}

impl Allocator {
    /// Build the allocator for a mutation: reclaim from the free-space tree if the
    /// volume has one, else append past the extent-tree high-water.
    pub async fn build<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> Result<Self, FsError> {
        let (root_tree, _) = vol.root_tree_root();
        let ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
            .await?
            .0;
        if let Ok((fst_root, _)) =
            roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID).await
        {
            // Reclaim from every free extent except those in a system block group
            // (reserved for the chunk tree).
            let bg_tree = block_group::bg_home(vol, root_tree).await?.scan_root(ext);
            let groups = read_block_group_types(vol, bg_tree).await?;
            let pinned = vol.pinned_ranges();
            let mut ranges: Vec<(u64, u64, u64)> = Vec::new();
            for (start, len) in read_free_extents(vol, fst_root).await? {
                // A free range lies inside one block group; one that matches
                // none (or straddles a boundary) is not offered at all.
                let Some(&(_, _, flags)) = groups.iter().find(|&&(s, l, _)| {
                    start >= s && start.saturating_add(len) <= s.saturating_add(l)
                }) else {
                    continue;
                };
                if flags & format::BLOCK_GROUP_SYSTEM != 0 {
                    continue;
                }
                // Withhold anything the in-flight transaction freed. A pinned
                // range can fall in the middle of a free one, so this
                // subtracts rather than filters — keeping the surviving
                // fragments usable instead of discarding a whole free extent.
                for (s, l) in subtract_pinned(alloc::vec![(start, len)], &pinned) {
                    ranges.push((s, l, flags));
                }
            }
            ranges.sort_unstable();
            return Ok(Allocator::Reclaim { ranges });
        }
        let hw = extent_high_water(vol, ext).await?.max(vol.alloc_floor());
        Ok(Allocator::Bump { next: hw })
    }

    /// Allocate `len` bytes aligned to `align`.
    fn alloc<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        len: u64,
        align: u64,
        kind: Kind,
    ) -> Result<u64, FsError> {
        let size = align_up(len, align).max(align);
        match self {
            // First-fit over the free extents (lowest address first). The chosen
            // extent lies wholly inside one block group / chunk, so the carved
            // range is physically contiguous by construction.
            Allocator::Reclaim { ranges } => {
                for i in 0..ranges.len() {
                    let (rs, rl, flags) = ranges[i];
                    if !kind.accepts(flags) {
                        continue;
                    }
                    let start = align_up(rs, align);
                    let end = start + size;
                    if end <= rs + rl {
                        // Replace the extent with its front pad and tail remainder.
                        let mut repl: Vec<(u64, u64, u64)> = Vec::new();
                        if start > rs {
                            repl.push((rs, start - rs, flags));
                        }
                        if end < rs + rl {
                            repl.push((end, rs + rl - end, flags));
                        }
                        ranges.splice(i..=i, repl);
                        return Ok(start);
                    }
                }
                Err(FsError::NoSpace)
            }
            // The range must stay in one logical chunk/block group. Physical
            // continuity is not required: the volume I/O layer splits RAID0/10/
            // 5/6 extents at stripe boundaries. An unmapped address (the cursor
            // ran past the last chunk) is out of space, not a lookup error.
            Allocator::Bump { next } => {
                // Without a free-space tree there is no per-group free map:
                // the bump cursor walks chunks in address order, which keeps
                // data and metadata apart only in mixed block groups. The
                // write-safety gate refuses read-write mounts of non-mixed
                // volumes without a free-space tree, so this path only ever
                // serves mixed ones.
                let _ = kind;
                let start = align_up(*next, align);
                let remaining = vol
                    .logical_chunk_remaining(start)
                    .map_err(|_| FsError::NoSpace)?;
                if size > remaining {
                    return Err(FsError::NoSpace);
                }
                *next = start + size;
                Ok(start)
            }
        }
    }

    /// Allocate one tree node (`nodesize`, node-aligned).
    pub fn alloc_node<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
    ) -> Result<u64, FsError> {
        let n = vol.nodesize() as u64;
        self.alloc(vol, n, n, Kind::Metadata)
    }

    /// Allocate a data extent of `len` bytes (sector-aligned).
    pub fn alloc_data<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        len: u64,
    ) -> Result<u64, FsError> {
        let s = u64::from(vol.sectorsize());
        self.alloc(vol, len, s, Kind::Data)
    }

    /// Snapshot the allocator's free state so the commit's metadata fixed point
    /// can re-hand-out the same addresses each round ([`Allocator::restore`]).
    pub fn snapshot(&self) -> Allocator {
        self.clone()
    }

    /// Restore a prior [`snapshot`](Allocator::snapshot).
    pub fn restore(&mut self, snap: &Allocator) {
        *self = snap.clone();
    }

    /// The session allocation floor to persist after the write, or `None` when
    /// reclaiming (the free-space tree is re-read at the start of each mutation,
    /// so no cross-write floor is needed).
    pub fn floor(&self) -> Option<u64> {
        match self {
            Allocator::Bump { next } => Some(*next),
            Allocator::Reclaim { .. } => None,
        }
    }
}
