//! Per-filesystem tree-log state: the space a log on disk occupies, and what
//! a transaction commit owes it.
//!
//! A tree log lives outside the committed trees. Its tree blocks, and the
//! data extents its file-extent items name, are free space as far as the
//! extent and free-space trees know, from the moment the log is written
//! until a commit makes the log obsolete. Linux covers that window in
//! memory: log blocks are allocations of the running transaction that never
//! get an extent item (`btrfs_alloc_tree_block` skips the delayed ref for
//! `BTRFS_TREE_LOG_OBJECTID`), are pinned when the log is freed at commit
//! (`btrfs_free_log` → `btrfs_pin_reserved_extent`), and at mount
//! `btrfs_recover_log_trees` pins every block of the log it is about to
//! replay (`btrfs_pin_extent_for_log_replay`) and excludes the logged data
//! extents (`btrfs_exclude_logged_extents`) before the first allocation.
//!
//! [`LogCore::pins`] is that set. Every allocator subtracts it
//! (`BtrfsVolume::pinned_ranges`), and [`on_commit`] hands it to the ordinary
//! pinned set, which is released only once the superblock that no longer
//! names the log is on the device.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use narf_block::BlockDevice;
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::format;
use crate::volume::BtrfsVolume;

/// No log replay is running.
const REPLAY_IDLE: u8 = 0;
/// A replay is applying the log: nothing may commit, because a committed
/// superblock in the middle of a replay would either drop the log with the
/// replay half done or keep a log whose generation no longer follows the
/// superblock's (which Linux refuses to mount).
const REPLAY_APPLYING: u8 = 1;
/// The replay is complete and its one transaction may commit.
const REPLAY_FINISHING: u8 = 2;

/// Tree-log state of one filesystem core.
#[derive(Debug)]
pub(crate) struct LogCore {
    /// Ranges a log on disk references that the committed trees hold free:
    /// its tree blocks and its not-yet-committed data extents.
    pins: IrqSafeSpinLock<Vec<(u64, u64)>>,
    replay: AtomicU8,
    /// Data checksums a running replay took from the log, by sector
    /// address, for the commit that ends the replay to write into the csum
    /// tree ([`take_replayed_csums`]).
    replayed_csums: IrqSafeSpinLock<BTreeMap<u64, Vec<u8>>>,
}

impl LogCore {
    pub(crate) fn new() -> Self {
        Self {
            pins: IrqSafeSpinLock::new(Vec::new()),
            replay: AtomicU8::new(REPLAY_IDLE),
            replayed_csums: IrqSafeSpinLock::new(BTreeMap::new()),
        }
    }

    /// The ranges every allocator must leave alone.
    pub(crate) fn pinned(&self) -> Vec<(u64, u64)> {
        self.pins.lock().clone()
    }

    /// Withhold `[start, start + len)` until the next commit's superblock is
    /// durable.
    pub(crate) fn pin(&self, start: u64, len: u64) {
        if len != 0 {
            self.pins.lock().push((start, len));
        }
    }

    pub(super) fn begin_replay(&self) {
        self.replayed_csums.lock().clear();
        self.replay.store(REPLAY_APPLYING, Ordering::Release);
    }

    /// Record the logged checksum of the data sector at `addr`.
    pub(super) fn replay_csum(&self, addr: u64, sum: &[u8]) {
        self.replayed_csums.lock().insert(addr, sum.to_vec());
    }

    pub(super) fn finish_replay(&self) {
        self.replay.store(REPLAY_FINISHING, Ordering::Release);
    }

    pub(super) fn end_replay(&self) {
        self.replayed_csums.lock().clear();
        self.replay.store(REPLAY_IDLE, Ordering::Release);
    }

    /// Drop every pin without a commit: the log they protected is gone from
    /// the superblock on disk.
    pub(super) fn release_pins(&self) -> Vec<(u64, u64)> {
        core::mem::take(&mut *self.pins.lock())
    }
}

/// What every transaction commit does for the tree log, on the superblock
/// image `raw` it is about to stage: Linux `btrfs_commit_transaction` zeroes
/// `super_copy->log_root` / `log_root_level` and frees the log trees
/// (`btrfs_free_log`, `btrfs_free_log_root_tree`), whose blocks stay pinned
/// until the superblock is written.
///
/// Fails, and so fails the commit, while a log replay is still applying.
pub(crate) fn on_commit<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
    raw: &mut [u8],
) -> Result<(), FsError> {
    let log = &vol.tree_log;
    if log.replay.load(Ordering::Acquire) == REPLAY_APPLYING {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "btrfs: a transaction tried to commit in the middle of a log replay; refusing"
        );
        return Err(FsError::InvalidData);
    }
    raw[format::OFF_LOG_ROOT..format::OFF_LOG_ROOT + 8].copy_from_slice(&0u64.to_le_bytes());
    raw[format::OFF_LOG_ROOT_TRANSID..format::OFF_LOG_ROOT_TRANSID + 8]
        .copy_from_slice(&0u64.to_le_bytes());
    raw[format::OFF_LOG_ROOT_LEVEL] = 0;
    // From here the staged image no longer names the log. Its space joins
    // what this transaction freed: withheld until that image is durable.
    for (start, len) in log.release_pins() {
        vol.pin_extent(start, len);
    }
    Ok(())
}

/// Most checksums one csum item written by replay holds.
const REPLAY_CSUMS_PER_ITEM: usize = 512;

/// The checksums a log replay took from the log, as csum-tree items
/// `(first sector address, packed checksums)` over runs of adjacent
/// sectors. Linux `replay_one_extent` deletes whatever the csum tree holds
/// for each replayed range (`btrfs_del_csums`) and inserts the logged sums
/// (`btrfs_csum_file_blocks`); the commit that ends the replay does both.
pub(crate) fn take_replayed_csums<B: BlockDevice + 'static>(
    vol: &BtrfsVolume<B>,
) -> Vec<(u64, Vec<u8>)> {
    let sums = core::mem::take(&mut *vol.tree_log.replayed_csums.lock());
    let sectorsize = u64::from(vol.sectorsize());
    let mut items: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut next = 0u64;
    let mut count = 0usize;
    for (addr, sum) in sums {
        match items.last_mut() {
            Some((_, body)) if addr == next && count < REPLAY_CSUMS_PER_ITEM => {
                body.extend_from_slice(&sum);
                count += 1;
            }
            _ => {
                items.push((addr, sum));
                count = 1;
            }
        }
        next = addr + sectorsize;
    }
    items
}
