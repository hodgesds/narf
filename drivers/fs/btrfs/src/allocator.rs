//! Space allocator for the COW write path.
//!
//! When the volume has a **free-space tree** (`space_cache=v2`), the allocator
//! *reclaims* space: it carves new data extents / tree nodes from the tree's
//! free ranges, so blocks freed by earlier transactions are reused. Blocks
//! freed by the **current** transaction are not yet in the tree (the
//! transaction returns them only on commit), so they stay unavailable until
//! it lands — preserving the COW invariant that old data is untouched until
//! the superblock flips.
//!
//! The free ranges are not re-read for every transaction. The filesystem
//! keeps one in-memory copy of the committed free-space tree
//! ([`FreeView`], Linux's per-block-group `btrfs_free_space_ctl` taken
//! together), loaded from disk once and then advanced by each commit with
//! exactly the allocations and frees that commit wrote into the tree
//! ([`FreeView::apply_commit`]). An allocator is that shared view plus the
//! ranges withheld from it: what this transaction has already handed out,
//! pinned extents, roots lock-free readers hold, and superblock mirrors. A
//! view is tied to the free-space tree root it mirrors, so anything that
//! moves the tree without advancing the view (a failed commit, the
//! whole-repack growth path, log replay) leaves it stale and it is reloaded.
//!
//! Data extents are carved first-fit from the lowest address. Tree blocks are
//! carved next-fit: each from the lowest free space at or after the end of
//! the last one, starting again from the bottom only when nothing above
//! fits, and across transactions (`BtrfsVolume::node_cursor`). Linux
//! allocates metadata the same way, from a cluster it works through
//! (`find_free_extent` with `fs_info->meta_alloc_cluster`). What it buys is
//! locality in the extent tree: the blocks one commit writes sit side by
//! side, so their `METADATA_ITEM`s share a leaf, and so do the items of the
//! blocks the next commit replaces. Filling the lowest holes instead puts
//! every commit's blocks wherever earlier ones happened to be freed, their
//! items in as many leaves, each of which the commit must then replace too
//! — a cost that grows with the tree, not with the transaction.
//!
//! Without a free-space tree it falls back to appending strictly **above** the
//! extent tree's high-water mark (freed space is not reused). Either way, running
//! out of space surfaces as `NoSpace`, which lets the caller grow the filesystem
//! and retry.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
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
/// Bitmap runs are emitted per bitmap item and flagged `true`;
/// [`FreeView::load`] joins the runs that continue across a bitmap boundary
/// inside one block group.
async fn read_free_extents<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    fst_root: u64,
) -> Result<Vec<(u64, u64, bool)>, FsError> {
    let ss = u64::from(vol.sectorsize());
    let mut cursor = Cursor::seek(vol, fst_root, &BtrfsKey::new(0, 0, 0)).await?;
    let mut out = Vec::new();
    while let Some((key, body)) = cursor.current()? {
        match key.item_type {
            format::FREE_SPACE_EXTENT_KEY => out.push((key.objectid, key.offset, false)),
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
                            out.push((s, key.objectid + bit as u64 * ss - s, true));
                            run_start = None;
                        }
                        _ => {}
                    }
                }
                if let Some(s) = run_start {
                    out.push((s, key.objectid + nbits as u64 * ss - s, true));
                }
            }
            _ => {}
        }
        cursor.advance().await?;
    }
    Ok(out)
}

/// `(start, len, flags)` of every block group, read from the
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

/// Whether [`FreeView::apply_commit`]'s result is re-read from disk and
/// compared after every commit ([`set_view_audit`]).
static VIEW_AUDIT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(cfg!(feature = "kernel-test"));

/// Turn the commit audit on or off: with it on, every commit re-reads the
/// free-space tree it just wrote and fails if the in-memory view it advanced
/// differs, and sums every block group's `used` and fails if that is not
/// what moving the superblock's `bytes_used` by its own changes gives (as
/// commits after a mount's first otherwise do). The audit reads the whole
/// free-space and block-group trees, so it is for tests and harnesses (it is
/// on by default in kernel-test builds), never for a production mount.
pub fn set_view_audit(on: bool) {
    VIEW_AUDIT.store(on, core::sync::atomic::Ordering::Release);
}

/// Whether the audit of [`set_view_audit`] is on.
pub(crate) fn view_audit() -> bool {
    VIEW_AUDIT.load(core::sync::atomic::Ordering::Acquire)
}

/// The committed free-space tree, in memory.
///
/// Linux keeps the same information per block group
/// (`btrfs_free_space_ctl`, filled by `btrfs_load_free_space_tree`) and
/// keeps it current as extents are allocated and as pinned extents are
/// returned by `btrfs_finish_extent_commit`. This is one map for the whole
/// filesystem, holding exactly what the free-space tree at `key` records —
/// freed-but-pinned space included, which each allocator withholds on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreeView {
    /// The free-space tree this mirrors: its root node's address and
    /// generation. A commit that moves the tree without advancing the view
    /// leaves the two different, and the view is reloaded.
    key: (u64, u64),
    /// Free ranges, `start -> (len, block group flags)`: sorted, disjoint and
    /// never spanning two block groups. They are the tree's own records —
    /// one per `FREE_SPACE_EXTENT` item, one per run of set bits of a bitmap
    /// block group — so a range the allocator carves from is always one the
    /// commit finds whole in the tree.
    ranges: BTreeMap<u64, (u64, u64)>,
    /// `(start, len, flags)` of every block group, sorted by start.
    groups: Vec<(u64, u64, u64)>,
    /// Free bytes per distinct block-group flags value.
    totals: BTreeMap<u64, u64>,
}

impl FreeView {
    /// The tree root this view mirrors, as `(address, generation)`.
    pub(crate) fn key(&self) -> (u64, u64) {
        self.key
    }

    /// The block group containing `addr`, as `(start, len, flags)`.
    fn group_of(&self, addr: u64) -> Option<(u64, u64, u64)> {
        let i = self.groups.partition_point(|&(start, _, _)| start <= addr);
        let group = *self.groups.get(i.checked_sub(1)?)?;
        (addr < group.0.saturating_add(group.1)).then_some(group)
    }

    /// Record `[start, start + len)` as free; with `join`, merged with a
    /// free neighbour on either side in the same block group, which is what
    /// freeing does in the tree (`add_free_space_extent`, or a run of bits
    /// growing). `None` when it lies in no single block group or overlaps
    /// space that is already free.
    fn insert(&mut self, start: u64, len: u64, join: bool) -> Option<()> {
        if len == 0 {
            return Some(());
        }
        let end = start.checked_add(len)?;
        let (bg_start, bg_len, flags) = self.group_of(start)?;
        if end > bg_start.saturating_add(bg_len) {
            return None;
        }
        let (mut new_start, mut new_end) = (start, end);
        if let Some((&ps, &(pl, _))) = self.ranges.range(..=start).next_back() {
            let pe = ps.saturating_add(pl);
            if pe > start {
                return None;
            }
            if join && pe == start && ps >= bg_start {
                new_start = ps;
            }
        }
        if let Some((&ns, &(nl, _))) = self.ranges.range(start..).next() {
            if ns < end {
                return None;
            }
            if join && ns == end && ns < bg_start.saturating_add(bg_len) {
                new_end = ns.saturating_add(nl);
                self.ranges.remove(&ns);
            }
        }
        if new_start != start {
            self.ranges.remove(&new_start);
        }
        self.ranges.insert(new_start, (new_end - new_start, flags));
        *self.totals.entry(flags).or_insert(0) += len;
        Some(())
    }

    /// Record `[start, start + len)` as used. `None` unless one free range
    /// contains all of it.
    fn remove(&mut self, start: u64, len: u64) -> Option<()> {
        if len == 0 {
            return Some(());
        }
        let end = start.checked_add(len)?;
        let (&rs, &(rl, flags)) = self.ranges.range(..=start).next_back()?;
        let re = rs.saturating_add(rl);
        if end > re {
            return None;
        }
        self.ranges.remove(&rs);
        if rs < start {
            self.ranges.insert(rs, (start - rs, flags));
        }
        if end < re {
            self.ranges.insert(end, (re - end, flags));
        }
        let total = self.totals.get_mut(&flags)?;
        *total = total.checked_sub(len)?;
        if *total == 0 {
            // As a fresh load would have it: no entry for a class with no
            // free space.
            self.totals.remove(&flags);
        }
        Some(())
    }

    /// Read the free-space tree rooted at `fst_root` (whose root node carries
    /// `generation`) and the block groups in `bg_tree`.
    async fn load<B: BlockDevice + 'static>(
        vol: &BtrfsVolume<B>,
        fst_root: u64,
        generation: u64,
        bg_tree: u64,
    ) -> Result<Self, FsError> {
        let mut groups = read_block_group_types(vol, bg_tree).await?;
        groups.sort_unstable();
        let mut view = FreeView {
            key: (fst_root, generation),
            ranges: BTreeMap::new(),
            groups,
            totals: BTreeMap::new(),
        };
        let mut ranges = read_free_extents(vol, fst_root).await?;
        ranges.sort_unstable();
        for (start, len, bitmap) in ranges {
            // A range outside every block group is not allocatable (and was
            // never offered); overlapping free ranges are a corrupt tree.
            if view.group_of(start).is_none() {
                continue;
            }
            // Extent items stay as recorded; a run of bits continues across
            // a bitmap item boundary.
            view.insert(start, len, bitmap)
                .ok_or(FsError::InvalidData)?;
        }
        Ok(view)
    }

    /// Advance the view across one commit: `used` ranges left free space and
    /// `freed` ranges joined it, and the tree now roots at `key`. `None` when
    /// the commit does not fit the view (it is then stale and must be
    /// dropped).
    pub(crate) fn apply_commit(
        &mut self,
        used: &[(u64, u64)],
        freed: &[(u64, u64)],
        key: (u64, u64),
    ) -> Option<()> {
        for &(start, len) in used {
            self.remove(start, len)?;
        }
        for &(start, len) in freed {
            self.insert(start, len, true)?;
        }
        self.key = key;
        Some(())
    }

    /// Whether `flags` is a block group an allocator of the given mode may
    /// carve from: SYSTEM groups only for the chunk tree's allocator, and
    /// only DATA / METADATA groups (never SYSTEM) for everyone else.
    fn usable(flags: u64, system: bool) -> bool {
        if system {
            flags & format::BLOCK_GROUP_SYSTEM != 0
        } else {
            flags & format::BLOCK_GROUP_SYSTEM == 0
                && flags & (format::BLOCK_GROUP_DATA | format::BLOCK_GROUP_METADATA) != 0
        }
    }
}

/// The filesystem's current [`FreeView`]: the cached one when it still
/// mirrors the committed free-space tree, else a fresh read of the tree
/// (which is then cached). `None` when the filesystem has no free-space tree.
/// The second value reports whether the tree was read from disk.
pub(crate) async fn current_view<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
) -> Result<Option<(Arc<FreeView>, bool)>, FsError> {
    let (root_tree, _) = vol.root_tree_root();
    let Ok((fst_root, _)) =
        roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID).await
    else {
        return Ok(None);
    };
    // The root node's own generation: with its address it names one version
    // of the tree, since a freed root block reused later is rewritten with a
    // newer generation.
    let generation = format::le64(&vol.read_node_shared(fst_root).await?, 80)?;
    if let Some(view) = vol.free_view() {
        if view.key == (fst_root, generation) {
            return Ok(Some((view, false)));
        }
    }
    let ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    let bg_tree = block_group::bg_home(vol, root_tree).await?.scan_root(ext);
    let view = Arc::new(FreeView::load(vol, fst_root, generation, bg_tree).await?);
    vol.set_free_view(Some(view.clone()));
    Ok(Some((view, true)))
}

/// Re-read the free-space tree and compare it with the cached view
/// ([`set_view_audit`]). `InvalidData` on any difference.
pub(crate) async fn audit_view<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
) -> Result<(), FsError> {
    let Some(cached) = vol.free_view() else {
        return Ok(());
    };
    let (root_tree, _) = vol.root_tree_root();
    let (fst_root, _) = roots::find_root(vol, root_tree, format::FREE_SPACE_TREE_OBJECTID).await?;
    let generation = format::le64(&vol.read_node_shared(fst_root).await?, 80)?;
    let ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
        .await?
        .0;
    let bg_tree = block_group::bg_home(vol, root_tree).await?.scan_root(ext);
    let disk = FreeView::load(vol, fst_root, generation, bg_tree).await?;
    if *cached != disk {
        use core::fmt::Write as _;
        let first = cached
            .ranges
            .iter()
            .zip(disk.ranges.iter())
            .find(|(a, b)| a != b);
        let _ = writeln!(
            narf_console::Writer,
            "btrfs: free-space view differs from the tree at {fst_root:#x} gen {generation}: \
             {} cached ranges (key {:?}), {} on disk; first difference {first:x?}; \
             groups equal {}, totals {:x?} vs {:x?}",
            cached.ranges.len(),
            cached.key,
            disk.ranges.len(),
            cached.groups == disk.groups,
            cached.totals,
            disk.totals
        );
        vol.set_free_view(None);
        return Err(FsError::InvalidData);
    }
    Ok(())
}

/// The part of a reclaiming allocator that changes as it hands out space.
#[derive(Clone, Debug, Default)]
pub struct Withheld {
    /// Ranges not to hand out, `start -> end`: sorted, disjoint, adjacent
    /// ones joined. What this allocator already allocated, plus the pinned,
    /// reader-held and superblock ranges it was built with.
    holes: BTreeMap<u64, u64>,
    /// Bytes of the view's free space under `holes`, per block-group flags.
    bytes: BTreeMap<u64, u64>,
    /// Per allocation class (0 metadata / system, 1 data): a request of at
    /// least `.0` bytes fits in no usable range starting below `.1`.
    hints: [(u64, u64); 2],
    /// End of the last tree block allocated, by this allocator or an earlier
    /// one of the filesystem: the next is carved at or after it when
    /// anything there fits.
    node_cursor: u64,
}

impl Withheld {
    /// Add `[start, end)` to the holes, joining neighbours.
    fn add(&mut self, mut start: u64, mut end: u64) {
        if start >= end {
            return;
        }
        if let Some((&ps, &pe)) = self.holes.range(..=start).next_back() {
            if pe >= start {
                start = ps;
                end = end.max(pe);
            }
        }
        let swallowed: Vec<u64> = self.holes.range(start..=end).map(|(&s, _)| s).collect();
        for s in swallowed {
            if let Some(e) = self.holes.remove(&s) {
                end = end.max(e);
            }
        }
        self.holes.insert(start, end);
    }

    /// The parts of `[start, end)` not under a hole, in address order.
    fn gaps(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut cur = start;
        if let Some((_, &pe)) = self.holes.range(..=start).next_back() {
            cur = cur.max(pe);
        }
        for (&hs, &he) in self.holes.range(start..end) {
            if hs > cur {
                out.push((cur, hs));
            }
            cur = cur.max(he);
        }
        if cur < end {
            out.push((cur, end));
        }
        out
    }

    /// Withhold `[start, start + len)` (an exclusion the allocator is built
    /// with), charging whatever part of it is free in `view`.
    fn exclude(&mut self, view: &FreeView, start: u64, len: u64) {
        let end = start.saturating_add(len);
        if start >= end {
            return;
        }
        let first = view
            .ranges
            .range(..=start)
            .next_back()
            .map_or(start, |(&rs, _)| rs);
        for (&rs, &(rl, flags)) in view.ranges.range(first..end) {
            let (lo, hi) = (rs.max(start), rs.saturating_add(rl).min(end));
            if lo >= hi {
                continue;
            }
            // Only what was not already withheld.
            let newly: u64 = self.gaps(lo, hi).iter().map(|&(s, e)| e - s).sum();
            *self.bytes.entry(flags).or_insert(0) += newly;
        }
        self.add(start, end);
    }
}

/// Counts the free ranges one allocation examines, for
/// [`crate::stats::Totals::alloc_ranges_examined`].
struct Examined(u64);

impl Drop for Examined {
    fn drop(&mut self) {
        crate::stats::note_alloc_ranges(self.0);
    }
}

/// A single mutation's space allocator: reclaiming from the free-space tree, or
/// appending past the extent-tree high-water when there is none.
#[derive(Clone, Debug)]
pub enum Allocator {
    /// Carve from the free-space tree's free ranges, lowest address first.
    /// Reused space comes first, so the tail free run is consumed only when
    /// needed. Each range carries its block group's type flags: a data
    /// extent is carved only from a DATA group and a tree block only from a
    /// METADATA group (mixed groups carry both bits), as Linux
    /// `find_free_extent` restricts each allocation to space_info of its
    /// type. SYSTEM groups (reserved for the chunk tree) are offered only to
    /// the chunk tree's own allocator (`system`).
    Reclaim {
        /// The committed free space, shared with the filesystem.
        view: Arc<FreeView>,
        /// What of it this allocator may not (or no longer) hand out.
        withheld: Withheld,
        /// An allocator over the SYSTEM block groups only.
        system: bool,
    },
    /// Append past the extent-tree high-water (no free-space tree present),
    /// stepping over `excluded` (superblock-covered) logical ranges.
    Bump {
        next: u64,
        excluded: Vec<(u64, u64)>,
    },
}

impl Allocator {
    /// Build the allocator for a mutation: reclaim from the free-space tree if the
    /// volume has one, else append past the extent-tree high-water.
    pub async fn build<B: BlockDevice + 'static>(vol: &BtrfsVolume<B>) -> Result<Self, FsError> {
        let started = narf_time::now_cycles();
        let Some((view, from_disk)) = current_view(vol).await? else {
            let (root_tree, _) = vol.root_tree_root();
            let ext = roots::find_root(vol, root_tree, format::EXTENT_TREE_OBJECTID)
                .await?
                .0;
            let hw = extent_high_water(vol, ext).await?.max(vol.alloc_floor());
            return Ok(Allocator::Bump {
                next: hw,
                excluded: vol.super_stripe_exclusions(),
            });
        };
        let mut withheld = Withheld {
            node_cursor: vol.node_cursor(),
            ..Withheld::default()
        };
        // Superblock copies under a chunk are never allocatable.
        for (start, len) in vol.super_stripe_exclusions() {
            withheld.exclude(&view, start, len);
        }
        // Nor a root a lock-free reader is still walking from.
        for (start, len) in vol.reader_root_ranges() {
            withheld.exclude(&view, start, len);
        }
        // Withhold anything a transaction freed that no durable superblock
        // has released yet. A pinned range can fall in the middle of a free
        // one; the surviving fragments stay usable.
        for (start, len) in vol.pinned_ranges() {
            withheld.exclude(&view, start, len);
        }
        vol.commit_stats()
            .note_alloc_build(narf_time::now_cycles().saturating_sub(started), from_disk);
        Ok(Allocator::Reclaim {
            view,
            withheld,
            system: false,
        })
    }

    /// An allocator over the SYSTEM block groups only, for the chunk tree's
    /// own blocks (which must stay reachable through `sys_chunk_array`).
    /// Requires a free-space tree.
    pub async fn build_system<B: BlockDevice + 'static>(
        vol: &BtrfsVolume<B>,
    ) -> Result<Self, FsError> {
        let (view, _) = current_view(vol).await?.ok_or(FsError::NotFound)?;
        let mut withheld = Withheld::default();
        for (start, len) in vol.super_stripe_exclusions() {
            withheld.exclude(&view, start, len);
        }
        for (start, len) in vol.pinned_ranges() {
            withheld.exclude(&view, start, len);
        }
        Ok(Allocator::Reclaim {
            view,
            withheld,
            system: true,
        })
    }

    /// Allocate one chunk-tree node from a SYSTEM group ([`Self::build_system`]).
    pub fn alloc_system_node<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
    ) -> Result<u64, FsError> {
        let n = vol.nodesize() as u64;
        self.alloc(vol, n, n, format::BLOCK_GROUP_SYSTEM)
    }

    /// Allocate `len` bytes aligned to `align` from a block group whose flags
    /// include `kind` (`BLOCK_GROUP_DATA` or `BLOCK_GROUP_METADATA`).
    fn alloc<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        len: u64,
        align: u64,
        kind: u64,
    ) -> Result<u64, FsError> {
        let size = align_up(len, align).max(align);
        match self {
            // First-fit over the free ranges (lowest address first). The
            // chosen range lies wholly inside one block group / chunk, so the
            // carved range is physically contiguous by construction.
            Allocator::Reclaim {
                view,
                withheld,
                system,
            } => {
                let class = usize::from(kind == format::BLOCK_GROUP_DATA);
                let mut examined = Examined(0);
                if kind == format::BLOCK_GROUP_METADATA && !*system {
                    // Next fit: the lowest space at or after the cursor,
                    // which may lie inside a range that starts below it.
                    let cursor = withheld.node_cursor;
                    let first = view
                        .ranges
                        .range(..=cursor)
                        .next_back()
                        .filter(|&(&rs, &(rl, _))| rs.saturating_add(rl) > cursor)
                        .map_or(cursor, |(&rs, _)| rs);
                    for (&rs, &(rl, flags)) in view.ranges.range(first..) {
                        examined.0 += 1;
                        if rl < size || flags & kind == 0 || !FreeView::usable(flags, *system) {
                            continue;
                        }
                        for (gs, ge) in withheld.gaps(rs, rs + rl) {
                            let start = align_up(gs.max(cursor), align);
                            let Some(end) = start.checked_add(size) else {
                                continue;
                            };
                            if end <= ge {
                                withheld.add(start, end);
                                *withheld.bytes.entry(flags).or_insert(0) += size;
                                withheld.node_cursor = end;
                                vol.set_node_cursor(end);
                                return Ok(start);
                            }
                        }
                    }
                    // Nothing above the cursor: start again from the bottom.
                }
                let (hint_size, hint_start) = withheld.hints[class];
                let from = if size >= hint_size { hint_start } else { 0 };
                for (&rs, &(rl, flags)) in view.ranges.range(from..) {
                    examined.0 += 1;
                    if rl < size || flags & kind == 0 || !FreeView::usable(flags, *system) {
                        continue;
                    }
                    for (gs, ge) in withheld.gaps(rs, rs + rl) {
                        let start = align_up(gs, align);
                        let Some(end) = start.checked_add(size) else {
                            continue;
                        };
                        if end <= ge {
                            withheld.add(start, end);
                            *withheld.bytes.entry(flags).or_insert(0) += size;
                            // Nothing below this range fitted `size`; a
                            // larger request cannot fit there either.
                            if size <= hint_size || from == 0 {
                                withheld.hints[class] = (size, rs);
                            }
                            if kind == format::BLOCK_GROUP_METADATA && !*system {
                                withheld.node_cursor = end;
                                vol.set_node_cursor(end);
                            }
                            return Ok(start);
                        }
                    }
                }
                Err(FsError::NoSpace)
            }
            // The range must stay in one logical chunk/block group. Physical
            // continuity is not required: the volume I/O layer splits RAID0/10/
            // 5/6 extents at stripe boundaries. An unmapped address (the cursor
            // ran past the last chunk) is out of space, not a lookup error.
            Allocator::Bump { next, excluded } => {
                let mut start = align_up(*next, align);
                while let Some(&(s, l)) = excluded
                    .iter()
                    .find(|&&(s, l)| start < s + l && start + size > s)
                {
                    start = align_up(s + l, align);
                }
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
        self.alloc(vol, n, n, format::BLOCK_GROUP_METADATA)
    }

    /// Allocate a data extent of `len` bytes (sector-aligned).
    pub fn alloc_data<B: BlockDevice + 'static>(
        &mut self,
        vol: &BtrfsVolume<B>,
        len: u64,
    ) -> Result<u64, FsError> {
        let s = u64::from(vol.sectorsize());
        self.alloc(vol, len, s, format::BLOCK_GROUP_DATA)
    }

    /// Bytes still free in block groups of `kind`; `u64::MAX` for the bump
    /// allocator, which does not know (it is never used under `root-rw`,
    /// which requires a free-space tree).
    pub fn free_bytes(&self, kind: u64) -> u64 {
        match self {
            Allocator::Reclaim {
                view,
                withheld,
                system,
            } => view
                .totals
                .iter()
                .filter(|&(&flags, _)| flags & kind != 0 && FreeView::usable(flags, *system))
                .map(|(flags, &total)| {
                    total.saturating_sub(withheld.bytes.get(flags).copied().unwrap_or(0))
                })
                .sum(),
            Allocator::Bump { .. } => u64::MAX,
        }
    }

    /// Test-only: every `(start, len, flags)` range this allocator may still
    /// carve from, withheld parts removed.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn __test_offered_ranges(&self) -> Vec<(u64, u64, u64)> {
        match self {
            Allocator::Reclaim {
                view,
                withheld,
                system,
            } => view
                .ranges
                .iter()
                .filter(|&(_, &(_, flags))| FreeView::usable(flags, *system))
                .flat_map(|(&start, &(len, flags))| {
                    withheld
                        .gaps(start, start + len)
                        .into_iter()
                        .map(move |(s, e)| (s, e - s, flags))
                })
                .collect(),
            Allocator::Bump { .. } => Vec::new(),
        }
    }

    /// How many block groups the filesystem has, and the bytes in those that
    /// hold metadata — `(u64::MAX, u64::MAX)` for the bump allocator, which
    /// does not know.
    pub(crate) fn group_shape(&self) -> (u64, u64) {
        match self {
            Allocator::Reclaim { view, .. } => (
                view.groups.len() as u64,
                view.groups
                    .iter()
                    .filter(|&&(_, _, flags)| flags & format::BLOCK_GROUP_METADATA != 0)
                    .map(|&(_, len, _)| len)
                    .sum(),
            ),
            Allocator::Bump { .. } => (u64::MAX, u64::MAX),
        }
    }

    /// Snapshot the allocator's free state, so a caller can hand out the
    /// same addresses again ([`Allocator::restore`]).
    pub fn snapshot(&self) -> Allocator {
        self.clone()
    }

    /// Restore a prior [`snapshot`](Allocator::snapshot).
    pub fn restore(&mut self, snap: &Allocator) {
        *self = snap.clone();
    }

    /// The session allocation floor to persist after the write, or `None` when
    /// reclaiming (the free-space view tracks every commit, so no cross-write
    /// floor is needed).
    pub fn floor(&self) -> Option<u64> {
        match self {
            Allocator::Bump { next, .. } => Some(*next),
            Allocator::Reclaim { .. } => None,
        }
    }
}
