//! Cheap per-filesystem counters of what transactions cost.
//!
//! They exist so a test (or a log line) can show that a commit's work
//! follows what the transaction changed and not the size of the filesystem.
//! Plain atomics, bumped once per node read or written and once per commit;
//! nothing is logged per block.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::format;

/// The most blocks any batch commit on any filesystem allocated beyond its
/// batch's reservation, i.e. took from the global reserve
/// ([`max_reserve_overrun`]).
static MAX_RESERVE_OVERRUN: AtomicU64 = AtomicU64::new(0);

/// The most tree blocks any batch commit (on any mounted btrfs since boot)
/// allocated beyond the reservation its batch held — what it drew from the
/// global reserve. For harnesses that judge the reservation's sizing.
pub fn max_reserve_overrun() -> u64 {
    MAX_RESERVE_OVERRUN.load(Relaxed)
}

/// Offset of the `owner` field in a tree-node header.
static FSYNC_LOGGED: AtomicU64 = AtomicU64::new(0);
static FSYNC_CLEAN: AtomicU64 = AtomicU64::new(0);
static FSYNC_COMMITTED: [AtomicU64; crate::write::tree_log::Fallback::ALL.len()] =
    [const { AtomicU64::new(0) }; crate::write::tree_log::Fallback::ALL.len()];

pub(crate) fn note_fsync_logged() {
    FSYNC_LOGGED.fetch_add(1, Relaxed);
}

pub(crate) fn note_fsync_clean() {
    FSYNC_CLEAN.fetch_add(1, Relaxed);
}

pub(crate) fn note_fsync_committed(why: usize) {
    if let Some(count) = FSYNC_COMMITTED.get(why) {
        count.fetch_add(1, Relaxed);
    }
}

/// How every `fsync`/`fdatasync` since boot was served, filesystem-wide:
/// `(through the tree log, nothing to make durable, by a full commit)`.
pub fn fsync_counts() -> (u64, u64, u64) {
    (
        FSYNC_LOGGED.load(Relaxed),
        FSYNC_CLEAN.load(Relaxed),
        FSYNC_COMMITTED.iter().map(|c| c.load(Relaxed)).sum(),
    )
}

/// Why fsyncs committed instead of logging: `(reason, count)` for every
/// reason that occurred.
pub fn fsync_fallbacks() -> alloc::vec::Vec<(&'static str, u64)> {
    crate::write::tree_log::Fallback::ALL
        .iter()
        .zip(&FSYNC_COMMITTED)
        .map(|(why, count)| (why.name(), count.load(Relaxed)))
        .filter(|&(_, count)| count != 0)
        .collect()
}

const HDR_OWNER: usize = 88;

/// Node counts split by the tree the node belongs to (its header's owner).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TreeCounts {
    pub root: u64,
    pub extent: u64,
    pub csum: u64,
    pub free_space: u64,
    pub block_group: u64,
    /// Subvolume, chunk, device, quota and every other tree.
    pub other: u64,
}

impl TreeCounts {
    /// Sum over every tree.
    pub fn total(&self) -> u64 {
        self.root + self.extent + self.csum + self.free_space + self.block_group + self.other
    }

    fn since(&self, earlier: &Self) -> Self {
        Self {
            root: self.root - earlier.root,
            extent: self.extent - earlier.extent,
            csum: self.csum - earlier.csum,
            free_space: self.free_space - earlier.free_space,
            block_group: self.block_group - earlier.block_group,
            other: self.other - earlier.other,
        }
    }
}

/// Running totals over every btrfs mounted since boot ([`totals`]), for
/// harnesses that judge what a commit costs: the difference of two samples
/// taken around one commit is that commit's cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    /// Transactions committed, and the passes they took to record their
    /// own blocks.
    pub commits: u64,
    pub rounds: u64,
    /// Tree nodes handed to a reader. Cache hits are included: this counts
    /// the blocks a walk visits, not device I/O.
    pub read: TreeCounts,
    /// Of those, the nodes that were read from the device (cache misses).
    pub device_reads: u64,
    /// Tree nodes written.
    pub written: TreeCounts,
    /// Free ranges the allocators examined to place data extents and tree
    /// blocks (first fit walks the free space until something fits).
    pub alloc_ranges_examined: u64,
    /// Not totals: the metadata blocks the last batch commit allocated for
    /// its own trees (the root tree's re-pack aside), and what its batch had
    /// reserved for them.
    pub last_commit_blocks: u64,
    pub last_commit_reserved: u64,
}

impl Totals {
    /// What happened between `earlier` and `self` (the `last_commit_*`
    /// fields are carried over as they are).
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            commits: self.commits - earlier.commits,
            rounds: self.rounds - earlier.rounds,
            read: self.read.since(&earlier.read),
            device_reads: self.device_reads - earlier.device_reads,
            written: self.written.since(&earlier.written),
            alloc_ranges_examined: self.alloc_ranges_examined - earlier.alloc_ranges_examined,
            last_commit_blocks: self.last_commit_blocks,
            last_commit_reserved: self.last_commit_reserved,
        }
    }
}

/// [`TreeCounts`] as atomics.
#[derive(Debug)]
struct TreeCounters([AtomicU64; 6]);

impl TreeCounters {
    const fn new() -> Self {
        Self([const { AtomicU64::new(0) }; 6])
    }

    fn bump(&self, node: &[u8]) {
        let slot = match format::le64(node, HDR_OWNER) {
            Ok(format::ROOT_TREE_OBJECTID) => 0,
            Ok(format::EXTENT_TREE_OBJECTID) => 1,
            Ok(format::CSUM_TREE_OBJECTID) => 2,
            Ok(format::FREE_SPACE_TREE_OBJECTID) => 3,
            Ok(format::BLOCK_GROUP_TREE_OBJECTID) => 4,
            _ => 5,
        };
        self.0[slot].fetch_add(1, Relaxed);
    }

    fn load(&self) -> TreeCounts {
        let at = |slot: usize| self.0[slot].load(Relaxed);
        TreeCounts {
            root: at(0),
            extent: at(1),
            csum: at(2),
            free_space: at(3),
            block_group: at(4),
            other: at(5),
        }
    }
}

static TOTAL_COMMITS: AtomicU64 = AtomicU64::new(0);
static TOTAL_ROUNDS: AtomicU64 = AtomicU64::new(0);
static TOTAL_READ: TreeCounters = TreeCounters::new();
static TOTAL_DEVICE_READS: AtomicU64 = AtomicU64::new(0);
static TOTAL_WRITTEN: TreeCounters = TreeCounters::new();
static TOTAL_ALLOC_RANGES: AtomicU64 = AtomicU64::new(0);
static LAST_COMMIT_BLOCKS: AtomicU64 = AtomicU64::new(0);
static LAST_COMMIT_RESERVED: AtomicU64 = AtomicU64::new(0);

/// The running [`Totals`].
pub fn totals() -> Totals {
    Totals {
        commits: TOTAL_COMMITS.load(Relaxed),
        rounds: TOTAL_ROUNDS.load(Relaxed),
        read: TOTAL_READ.load(),
        device_reads: TOTAL_DEVICE_READS.load(Relaxed),
        written: TOTAL_WRITTEN.load(),
        alloc_ranges_examined: TOTAL_ALLOC_RANGES.load(Relaxed),
        last_commit_blocks: LAST_COMMIT_BLOCKS.load(Relaxed),
        last_commit_reserved: LAST_COMMIT_RESERVED.load(Relaxed),
    }
}

/// Count the free ranges one allocation examined.
pub(crate) fn note_alloc_ranges(examined: u64) {
    TOTAL_ALLOC_RANGES.fetch_add(examined, Relaxed);
}

/// Count one node read from the device (a node-cache miss).
pub(crate) fn note_device_read() {
    TOTAL_DEVICE_READS.fetch_add(1, Relaxed);
}

/// Counters of one mounted filesystem ([`crate::volume::VolCore`]).
#[derive(Debug, Default)]
pub(crate) struct CommitStats {
    /// Free-space-tree nodes read. Cache hits are included: this counts the
    /// blocks a walk visits, not device I/O.
    pub(crate) fst_nodes_read: AtomicU64,
    /// Free-space-tree nodes written.
    pub(crate) fst_nodes_written: AtomicU64,
    /// Metadata nodes of every tree written.
    pub(crate) meta_nodes_written: AtomicU64,
    /// Transactions committed.
    pub(crate) commits: AtomicU64,
    /// Passes of recording a commit's own blocks, over all commits and of
    /// the last one.
    pub(crate) rounds: AtomicU64,
    pub(crate) last_rounds: AtomicU64,
    /// Allocators built, how many of those read the free-space tree from
    /// disk, and the cycles spent building.
    pub(crate) alloc_builds: AtomicU64,
    pub(crate) alloc_disk_builds: AtomicU64,
    pub(crate) alloc_build_cycles: AtomicU64,
    /// Superblock images written to the device.
    pub(crate) super_writes: AtomicU64,
    /// Operations refused before staging because their metadata reservation
    /// did not fit (each is then retried after reclaim, or gets `ENOSPC`).
    pub(crate) reserve_refusals: AtomicU64,
    /// METADATA chunks allocated ahead of need, because a refused
    /// reservation found the metadata space past Linux's 80% threshold.
    pub(crate) early_metadata_chunks: AtomicU64,
    /// Metadata blocks the last commit allocated for itself (csum, extent,
    /// block-group, free-space and root trees), and the first-order
    /// reservation its batch held for them; the most any commit exceeded its
    /// reservation by (what it took from the global reserve).
    pub(crate) last_commit_blocks: AtomicU64,
    pub(crate) last_commit_reserved: AtomicU64,
    pub(crate) max_reserve_overrun: AtomicU64,
    /// The reservation of the batch about to commit, plus one (0: the next
    /// commit is not a batch's). Set by the batch, taken by its commit.
    pub(crate) pending_reservation: AtomicU64,
}

/// A point-in-time copy of [`CommitStats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CommitStatsSnapshot {
    pub(crate) fst_nodes_read: u64,
    pub(crate) fst_nodes_written: u64,
    pub(crate) meta_nodes_written: u64,
    pub(crate) commits: u64,
    pub(crate) rounds: u64,
    pub(crate) last_rounds: u64,
    pub(crate) alloc_builds: u64,
    pub(crate) alloc_disk_builds: u64,
    pub(crate) alloc_build_cycles: u64,
    pub(crate) super_writes: u64,
    pub(crate) reserve_refusals: u64,
    pub(crate) early_metadata_chunks: u64,
    pub(crate) max_reserve_overrun: u64,
}

impl CommitStatsSnapshot {
    /// What happened between `earlier` and `self` (`last_rounds` is not a
    /// running total and is carried over as is).
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn since(&self, earlier: &Self) -> Self {
        Self {
            fst_nodes_read: self.fst_nodes_read - earlier.fst_nodes_read,
            fst_nodes_written: self.fst_nodes_written - earlier.fst_nodes_written,
            meta_nodes_written: self.meta_nodes_written - earlier.meta_nodes_written,
            commits: self.commits - earlier.commits,
            rounds: self.rounds - earlier.rounds,
            last_rounds: self.last_rounds,
            alloc_builds: self.alloc_builds - earlier.alloc_builds,
            alloc_disk_builds: self.alloc_disk_builds - earlier.alloc_disk_builds,
            alloc_build_cycles: self.alloc_build_cycles - earlier.alloc_build_cycles,
            super_writes: self.super_writes - earlier.super_writes,
            reserve_refusals: self.reserve_refusals - earlier.reserve_refusals,
            early_metadata_chunks: self.early_metadata_chunks - earlier.early_metadata_chunks,
            max_reserve_overrun: self.max_reserve_overrun,
        }
    }
}

impl CommitStats {
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
    pub(crate) fn snapshot(&self) -> CommitStatsSnapshot {
        CommitStatsSnapshot {
            fst_nodes_read: self.fst_nodes_read.load(Relaxed),
            fst_nodes_written: self.fst_nodes_written.load(Relaxed),
            meta_nodes_written: self.meta_nodes_written.load(Relaxed),
            commits: self.commits.load(Relaxed),
            rounds: self.rounds.load(Relaxed),
            last_rounds: self.last_rounds.load(Relaxed),
            alloc_builds: self.alloc_builds.load(Relaxed),
            alloc_disk_builds: self.alloc_disk_builds.load(Relaxed),
            alloc_build_cycles: self.alloc_build_cycles.load(Relaxed),
            super_writes: self.super_writes.load(Relaxed),
            reserve_refusals: self.reserve_refusals.load(Relaxed),
            early_metadata_chunks: self.early_metadata_chunks.load(Relaxed),
            max_reserve_overrun: self.max_reserve_overrun.load(Relaxed),
        }
    }

    /// Count one node handed to a reader.
    pub(crate) fn note_read(&self, node: &[u8]) {
        TOTAL_READ.bump(node);
        if format::le64(node, HDR_OWNER).ok() == Some(format::FREE_SPACE_TREE_OBJECTID) {
            self.fst_nodes_read.fetch_add(1, Relaxed);
        }
    }

    /// Count one node about to be written.
    pub(crate) fn note_write(&self, node: &[u8]) {
        TOTAL_WRITTEN.bump(node);
        self.meta_nodes_written.fetch_add(1, Relaxed);
        if format::le64(node, HDR_OWNER).ok() == Some(format::FREE_SPACE_TREE_OBJECTID) {
            self.fst_nodes_written.fetch_add(1, Relaxed);
        }
    }

    /// Count one finished commit that recorded its blocks in `rounds`
    /// passes.
    pub(crate) fn note_commit(&self, rounds: u64) {
        TOTAL_COMMITS.fetch_add(1, Relaxed);
        TOTAL_ROUNDS.fetch_add(rounds, Relaxed);
        self.commits.fetch_add(1, Relaxed);
        self.rounds.fetch_add(rounds, Relaxed);
        self.last_rounds.store(rounds, Relaxed);
    }

    /// A batch holding a reservation of `blocks` is about to commit.
    pub(crate) fn expect_commit(&self, blocks: u64) {
        self.pending_reservation
            .store(blocks.saturating_add(1), Relaxed);
    }

    /// The commit that just settled allocated `blocks` for its own trees
    /// (the root tree's re-pack aside). Returns how far that went past the
    /// committing batch's reservation, if it was a batch's commit.
    pub(crate) fn note_commit_blocks(&self, blocks: u64) -> Option<u64> {
        let reserved = self.pending_reservation.swap(0, Relaxed).checked_sub(1)?;
        self.last_commit_blocks.store(blocks, Relaxed);
        self.last_commit_reserved.store(reserved, Relaxed);
        LAST_COMMIT_BLOCKS.store(blocks, Relaxed);
        LAST_COMMIT_RESERVED.store(reserved, Relaxed);
        let overrun = blocks.saturating_sub(reserved);
        self.max_reserve_overrun.fetch_max(overrun, Relaxed);
        MAX_RESERVE_OVERRUN.fetch_max(overrun, Relaxed);
        Some(overrun)
    }

    /// Count one allocator build that took `cycles`.
    pub(crate) fn note_alloc_build(&self, cycles: u64, from_disk: bool) {
        self.alloc_builds.fetch_add(1, Relaxed);
        self.alloc_build_cycles.fetch_add(cycles, Relaxed);
        if from_disk {
            self.alloc_disk_builds.fetch_add(1, Relaxed);
        }
    }
}
