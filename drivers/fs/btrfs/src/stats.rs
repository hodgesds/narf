//! Cheap per-filesystem counters of what transactions cost.
//!
//! They exist so a test (or a log line) can show that a commit's work
//! follows what the transaction changed and not the size of the filesystem.
//! Plain atomics, bumped once per node read or written and once per commit;
//! nothing is logged per block.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::format;

/// Offset of the `owner` field in a tree-node header.
const HDR_OWNER: usize = 88;

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
    /// Fixed-point rounds over all commits, and of the last one.
    pub(crate) rounds: AtomicU64,
    pub(crate) last_rounds: AtomicU64,
    /// Allocators built, how many of those read the free-space tree from
    /// disk, and the cycles spent building.
    pub(crate) alloc_builds: AtomicU64,
    pub(crate) alloc_disk_builds: AtomicU64,
    pub(crate) alloc_build_cycles: AtomicU64,
    /// Superblock images written to the device.
    pub(crate) super_writes: AtomicU64,
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
        }
    }

    /// Count one node handed to a reader.
    pub(crate) fn note_read(&self, node: &[u8]) {
        if format::le64(node, HDR_OWNER).ok() == Some(format::FREE_SPACE_TREE_OBJECTID) {
            self.fst_nodes_read.fetch_add(1, Relaxed);
        }
    }

    /// Count one node about to be written.
    pub(crate) fn note_write(&self, node: &[u8]) {
        self.meta_nodes_written.fetch_add(1, Relaxed);
        if format::le64(node, HDR_OWNER).ok() == Some(format::FREE_SPACE_TREE_OBJECTID) {
            self.fst_nodes_written.fetch_add(1, Relaxed);
        }
    }

    /// Count one finished commit that took `rounds` fixed-point rounds.
    pub(crate) fn note_commit(&self, rounds: u64) {
        self.commits.fetch_add(1, Relaxed);
        self.rounds.fetch_add(rounds, Relaxed);
        self.last_rounds.store(rounds, Relaxed);
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
