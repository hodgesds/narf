//! Read repair: rewrite a bad mirror copy from a good one (Linux
//! `btrfs_repair_io_failure` in `fs/btrfs/bio.c`, called for metadata by
//! `btrfs_repair_eb_io_failure` from `btrfs_read_extent_buffer` and for data
//! by `btrfs_end_repair_bio` once a mirror passed `btrfs_data_csum_ok`), and
//! the per-device error counters it keeps (`btrfs_dev_stat_inc_and_print`).
//!
//! # Why a repair write is safe
//!
//! btrfs is copy-on-write: a referenced tree block or data extent is never
//! rewritten in place, so the bytes a reader just verified on one mirror are
//! what every mirror of that logical range must hold — unless the range was
//! freed and reallocated after the read, or a write to it is in flight. NARF
//! has two more ways a logical range is rewritten (see the btrfs spec §4):
//! a batch writes its blocks out operation by operation, and chunk
//! relocation copies a chunk's stripes. Neither rewrites a block a reader can
//! reach without passing through a fresh write of every mirror.
//!
//! So the rule here is stronger than "the extent is still allocated": a
//! repair writes the bad copy only
//!
//! 1. on a writable, healthy filesystem (not read-only, not degraded, not
//!    aborted — Linux `sb_rdonly`), with checksums verified;
//! 2. for a direct mirror of a non-RAID5/6 chunk whose bad stripe covers no
//!    superblock copy (Linux repairs superblocks only through a commit);
//! 3. while no write to any byte of the range is in flight, and with every
//!    new write to it held off until the repair is done ([`IoRanges`]: every
//!    logical write registers its range, a repair registers its own and
//!    gives up if a write is already running there);
//! 4. after re-reading, under that exclusion, the good copy and finding it
//!    byte-identical to what was verified (a range rewritten since — freed,
//!    reallocated, written — no longer matches); and the bad copy still
//!    failing the same verification (a copy that now verifies is left alone,
//!    even if it differs: two valid copies is not something to resolve here).
//!
//! Under 3 and 4 the repair writes exactly what the good mirror holds at that
//! instant with no write to the range able to land in between, so it cannot
//! make the mirrors disagree about any content a tree references.

#[cfg(feature = "kernel-test")]
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

/// `BTRFS_DEV_STAT_*` indices (`include/uapi/linux/btrfs.h`).
pub(crate) const DEV_STAT_WRITE_ERRS: usize = 0;
pub(crate) const DEV_STAT_READ_ERRS: usize = 1;
pub(crate) const DEV_STAT_FLUSH_ERRS: usize = 2;
pub(crate) const DEV_STAT_CORRUPTION_ERRS: usize = 3;
pub(crate) const DEV_STAT_GENERATION_ERRS: usize = 4;
const DEV_STAT_VALUES_MAX: usize = 5;

/// Logical ranges being written, and ranges being repaired.
#[derive(Default)]
struct RangesInner {
    next: u64,
    /// In-flight writes: id → `[start, end)`.
    writes: BTreeMap<u64, (u64, u64)>,
    /// In-flight repairs: id → `[start, end)`.
    repairs: BTreeMap<u64, (u64, u64)>,
    /// Writers parked behind a repair.
    waiters: Vec<Waker>,
}

fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

/// The exclusion between logical writes and repair writes (rule 3 of the
/// module documentation). Writers never wait for each other here, only for a
/// repair of an overlapping range; a repair never waits at all.
pub(crate) struct IoRanges {
    inner: IrqSafeSpinLock<RangesInner>,
}

impl Default for IoRanges {
    fn default() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(RangesInner::default()),
        }
    }
}

impl core::fmt::Debug for IoRanges {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let g = self.inner.lock();
        f.debug_struct("IoRanges")
            .field("writes", &g.writes.len())
            .field("repairs", &g.repairs.len())
            .finish()
    }
}

/// A registered write; unregisters on drop.
pub(crate) struct WriteRange<'a> {
    ranges: &'a IoRanges,
    id: u64,
}

impl Drop for WriteRange<'_> {
    fn drop(&mut self) {
        self.ranges.inner.lock().writes.remove(&self.id);
    }
}

/// A registered repair; unregisters on drop and wakes the writers it held.
pub(crate) struct RepairRange<'a> {
    ranges: &'a IoRanges,
    id: u64,
}

impl Drop for RepairRange<'_> {
    fn drop(&mut self) {
        let waiters = {
            let mut g = self.ranges.inner.lock();
            g.repairs.remove(&self.id);
            core::mem::take(&mut g.waiters)
        };
        for waker in waiters {
            waker.wake();
        }
    }
}

impl IoRanges {
    /// Register a write of `[logical, logical + len)`, first waiting out any
    /// repair of an overlapping range.
    pub(crate) async fn begin_write(&self, logical: u64, len: u64) -> WriteRange<'_> {
        let range = (logical, logical.saturating_add(len));
        core::future::poll_fn(|cx| {
            let mut g = self.inner.lock();
            if g.repairs.values().any(|r| overlaps(*r, range)) {
                if !g.waiters.iter().any(|w| w.will_wake(cx.waker())) {
                    g.waiters.push(cx.waker().clone());
                }
                return Poll::Pending;
            }
            g.next += 1;
            let id = g.next;
            g.writes.insert(id, range);
            Poll::Ready(WriteRange { ranges: self, id })
        })
        .await
    }

    /// Register a repair of `[logical, logical + len)`, or `None` when a
    /// write to any byte of it is in flight (the range is being rewritten,
    /// on every mirror, by someone else).
    pub(crate) fn try_begin_repair(&self, logical: u64, len: u64) -> Option<RepairRange<'_>> {
        let range = (logical, logical.saturating_add(len));
        let mut g = self.inner.lock();
        if g.writes.values().any(|w| overlaps(*w, range))
            || g.repairs.values().any(|r| overlaps(*r, range))
        {
            return None;
        }
        g.next += 1;
        let id = g.next;
        g.repairs.insert(id, range);
        Some(RepairRange { ranges: self, id })
    }

    /// Test-only: writes and repairs registered right now.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn in_flight(&self) -> (usize, usize) {
        let g = self.inner.lock();
        (g.writes.len(), g.repairs.len())
    }
}

/// Outcome counters of read repair, for tests and diagnostics.
#[derive(Debug, Default)]
pub(crate) struct RepairCounters {
    /// Bad copies rewritten from a good one.
    pub repaired: AtomicU64,
    /// Skipped: read-only, degraded or aborted filesystem, or checksums off.
    pub skipped_read_only: AtomicU64,
    /// Skipped: a write to the range was in flight.
    pub skipped_busy: AtomicU64,
    /// Skipped: the good copy changed, or the bad copy now verifies.
    pub skipped_changed: AtomicU64,
    /// Skipped: a shape repair does not handle (RAID5/6, a range split
    /// across stripes, a superblock copy in the way, a missing member).
    pub skipped_unsupported: AtomicU64,
    /// The repair write failed.
    pub failed: AtomicU64,
}

/// Snapshot of [`RepairCounters`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairStats {
    pub repaired: u64,
    pub skipped_read_only: u64,
    pub skipped_busy: u64,
    pub skipped_changed: u64,
    pub skipped_unsupported: u64,
    pub failed: u64,
}

impl RepairCounters {
    pub(crate) fn snapshot(&self) -> RepairStats {
        let r = |c: &AtomicU64| c.load(Ordering::Relaxed);
        RepairStats {
            repaired: r(&self.repaired),
            skipped_read_only: r(&self.skipped_read_only),
            skipped_busy: r(&self.skipped_busy),
            skipped_changed: r(&self.skipped_changed),
            skipped_unsupported: r(&self.skipped_unsupported),
            failed: r(&self.failed),
        }
    }

    pub(crate) fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Per-device error counters (`btrfs_device::dev_stat_values`), in memory.
/// Linux also persists them in the device tree's `DEV_STATS` item at commit
/// (`btrfs_run_dev_stats`); NARF does not yet.
pub(crate) struct DevStats {
    values: IrqSafeSpinLock<BTreeMap<u64, [u32; DEV_STAT_VALUES_MAX]>>,
}

impl Default for DevStats {
    fn default() -> Self {
        Self {
            values: IrqSafeSpinLock::new(BTreeMap::new()),
        }
    }
}

impl core::fmt::Debug for DevStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_map().entries(self.values.lock().iter()).finish()
    }
}

impl DevStats {
    /// `btrfs_dev_stat_inc_and_print`: count one error of kind `index` on
    /// `devid` and print the device's counters (rate-limited, as
    /// `btrfs_err_rl`).
    pub(crate) fn inc_and_print(&self, devid: u64, index: usize) {
        let v = {
            let mut g = self.values.lock();
            let v = g.entry(devid).or_default();
            v[index] = v[index].saturating_add(1);
            *v
        };
        if ERR_LIMIT.allow() {
            let _ = writeln!(
                narf_console::Writer,
                "BTRFS error: bdev devid {devid} errs: wr {}, rd {}, flush {}, corrupt {}, gen {}",
                v[DEV_STAT_WRITE_ERRS],
                v[DEV_STAT_READ_ERRS],
                v[DEV_STAT_FLUSH_ERRS],
                v[DEV_STAT_CORRUPTION_ERRS],
                v[DEV_STAT_GENERATION_ERRS],
            );
        }
    }

    /// The counters of `devid` (`BTRFS_IOC_GET_DEV_STATS` order).
    pub fn get(&self, devid: u64) -> [u32; DEV_STAT_VALUES_MAX] {
        self.values.lock().get(&devid).copied().unwrap_or_default()
    }
}

/// Linux `printk_limits` for btrfs messages: 100 per 5 s
/// (`DEFAULT_RATELIMIT_INTERVAL`), shared by every filesystem.
pub(crate) struct RateLimit {
    state: IrqSafeSpinLock<(u64, u32, u64)>, // (window start ns, printed, missed)
    interval_ns: u64,
    burst: u32,
}

impl RateLimit {
    pub(crate) const fn new(interval_ns: u64, burst: u32) -> Self {
        Self {
            state: IrqSafeSpinLock::new((0, 0, 0)),
            interval_ns,
            burst,
        }
    }

    /// Whether one more message may print now (`__ratelimit`).
    pub(crate) fn allow(&self) -> bool {
        let now = narf_time::monotonic_ns();
        let (allowed, missed) = {
            let mut g = self.state.lock();
            let mut missed = 0;
            if g.0 == 0 || now.saturating_sub(g.0) >= self.interval_ns {
                missed = g.2;
                *g = (now.max(1), 0, 0);
            }
            if g.1 < self.burst {
                g.1 += 1;
                (true, missed)
            } else {
                g.2 += 1;
                (false, missed)
            }
        };
        if missed > 0 {
            let _ = writeln!(narf_console::Writer, "btrfs: {missed} messages suppressed");
        }
        allowed
    }

    /// Messages refused in the current window.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn suppressed(&self) -> u64 {
        self.state.lock().2
    }
}

/// The limiters of `btrfs_err_rl` (device error counters) and
/// `btrfs_info_rl` (repair messages): one per log level, as Linux's
/// `printk_limits[level]`.
pub(crate) static ERR_LIMIT: RateLimit = RateLimit::new(5_000_000_000, 100);
pub(crate) static INFO_LIMIT: RateLimit = RateLimit::new(5_000_000_000, 100);

/// Messages printed by [`report_corrected`] (for the rate-limit test).
pub(crate) static CORRECTED_PRINTED: AtomicU64 = AtomicU64::new(0);

/// `"read error corrected: ino %llu off %llu (dev %s sector %llu)"`
/// (`btrfs_info_rl`). Metadata reports `ino 0` and the block's logical
/// address, as `btrfs_repair_eb_io_failure` passes them.
pub(crate) fn report_corrected(ino: u64, off: u64, devid: u64, physical: u64) {
    if INFO_LIMIT.allow() {
        CORRECTED_PRINTED.fetch_add(1, Ordering::Relaxed);
        let _ = writeln!(
            narf_console::Writer,
            "BTRFS info: read error corrected: ino {ino} off {off} (dev devid {devid} sector {})",
            physical >> 9
        );
    }
}

/// A parent's check of a child block read through its pointer (Linux
/// `btrfs_tree_parent_check`: generation, level, first key).
pub(crate) type ParentCheck<'a> = &'a (dyn Fn(&[u8]) -> bool + Sync);

/// What makes a copy good: a tree block's own bytenr and checksum, or a data
/// sector's stored checksum.
#[derive(Clone, Copy)]
pub(crate) enum Verify<'a> {
    /// A tree block, with its parent's check of it when it was reached
    /// through a parent pointer (generation, level, first key).
    Node(Option<ParentCheck<'a>>),
    Data(&'a [u8]),
}

/// One repair request: the range just verified good on `good_copy`, and the
/// copies that failed before it.
pub(crate) struct Request<'a> {
    pub logical: u64,
    pub good: &'a [u8],
    pub good_copy: usize,
    /// Bit `i` set: direct copy `i` failed verification or could not be read.
    pub bad: u32,
    pub verify: Verify<'a>,
    /// `(ino, file offset)` for the message; metadata passes `(0, logical)`.
    pub owner: (u64, u64),
}

/// Test hook run between a read's verification and its repair: it can free,
/// reallocate or rewrite the range, or start a write to it.
#[cfg(feature = "kernel-test")]
pub(crate) struct RepairHook(pub Box<dyn Fn(u64) + Send + Sync>);

#[cfg(feature = "kernel-test")]
impl core::fmt::Debug for RepairHook {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RepairHook")
    }
}
