//! Interval notifiers over user address ranges: the subset of Linux
//! `mm/mmu_notifier.c` (`mmu_interval_notifier_insert`/`_remove`,
//! `mmu_interval_read_begin`/`_read_retry`/`_check_retry`/`_set_seq`) that a
//! device mirror of user memory needs.
//!
//! A consumer registers `[start, start + length)` of one [`AddressSpace`].
//! Whenever an address-space operation changes or removes the translation of
//! a page in that range, the registry assigns a fresh sequence number, stores
//! it in the interval and calls the consumer's
//! [`MmuIntervalNotifierOps::invalidate`]. The consumer brackets every
//! (re)collection of the range's pages with [`MmuInterval::read_begin`] and
//! [`MmuInterval::read_retry`]: if any invalidation fired in between, the
//! collected pages are stale and must be dropped and collected again.
//!
//! # Firing operations (`MmuNotifierEvent`)
//!
//! | Operation | Event |
//! | --- | --- |
//! | `munmap`, `MAP_FIXED` replacement, brk shrink (`punch_fixed*`), `unmap_region`, `unmap_huge_region` | `Unmap` |
//! | `mremap` move / `MREMAP_DONTUNMAP`: the source range (`relocate_*`, `dontunmap_*`) | `Unmap` |
//! | OOM reaper (`reap_anonymous_owned`) | `Unmap` |
//! | `unmap_mapping_range` truncate zap, `MADV_DONTNEED`, `MADV_GUARD_INSTALL` | `Clear` |
//! | COW break (`cow_split_mode`, reached by write faults and `FOLL_WRITE` pins) | `Clear` |
//! | swap-out, `MADV_FREE` lazy discard | `Clear` |
//! | `mprotect`/`change_perms_range` that removes READ or WRITE | `ProtectionVma` |
//! | page migration that installs a new frame (`relocate_leaf`, huge migration, multi-owner `repoint_shared_page`) | `Migrate` |
//! | process exit (`reclaim_unshared_on_exit`) and final `Drop` | `Release` |
//!
//! Operations that never change which frame a VA translates to do not fire:
//! fork (pinned private pages are copied for the child and the parent keeps
//! its leaf), NUMA hint protection (the frame is unchanged and restoring or
//! migrating it goes through the migration row), growth, and mapping new
//! pages. Shared-frame replacement (`replace_shared_frame`,
//! `with_revoked_shared_frames`) and single-owner migration refuse pinned
//! frames, so a consumer's pinned view is never moved by them.
//!
//! # Locking and the callback contract
//!
//! Every firing site calls into the registry while it still holds the
//! address-space lock that serializes the translation change it is making:
//! the region-table lock for base pages, the huge-region lock for huge pages
//! (plus the VMA transaction and shared-mapping shard where the operation
//! already holds them). Those locks are `IrqSafeSpinLock`s, so a callback runs
//! with interrupts masked and **must not** block, sleep, await, fault on user
//! memory, allocate infallibly, take any address-space lock, pin user pages,
//! or insert, remove or drop an interval notifier. The only lock a callback
//! may take is a leaf lock of its own that is never held while calling into
//! this crate. The lock order is therefore
//!
//! ```text
//! VMA transaction -> shared-mapping shard -> huge regions -> regions
//!     -> notifier registry shard -> consumer leaf lock
//! ```
//!
//! and nothing in this module acquires an address-space lock, so callbacks
//! cannot deadlock the mm. [`MmuNotifierRange::blockable`] is always `false`
//! (Linux's non-blocking invalidation).
//!
//! # What "invalidation complete" means here
//!
//! The registry publishes the new sequence before invoking the callback, and
//! every firing site fires before it releases the frames the operation
//! retires. A consumer that lets a device reach user memory must reach it
//! only through `UserPagePin`s taken inside a `read_begin`/`read_retry`
//! section that began after `insert` returned. A pin holds a frame reference,
//! so a retired frame is not returned to the allocator while the device can
//! still reach it, and a callback that cannot block may complete
//! asynchronously: the consumer stops new device use at once and drops its
//! pins after the device has stopped. Unlike Linux, NARF does not support
//! consumers that mirror memory without pins.
//!
//! # Registry
//!
//! Intervals live in 64 shards selected by address-space identity, each a
//! vector sorted by (address space, start) that is grown only outside its
//! IRQ-masked lock. A firing site finds its own space's run by binary search
//! and visits only intervals starting below the operation's end; a space may
//! hold at most [`MAX_INTERVALS_PER_SPACE`], which bounds that scan. With no
//! interval registered anywhere, a firing site costs one atomic load.
//!
//! # Why `read_begin` does not wait
//!
//! Linux's `mmu_interval_read_begin` sleeps while an invalidation of the
//! interval is between `invalidate_range_start` and `_end`. Here the sequence
//! update, the callback and the translation change all happen inside one hold
//! of the lock that `AddressSpace::pin_user_page` must take, so a reader that
//! observes the new sequence cannot pin until the change has committed.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::address_space::AddressSpace;

/// Why the translation of a notified range changed (Linux
/// `enum mmu_notifier_event`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MmuNotifierEvent {
    /// The range stopped being mapped: munmap, MAP_FIXED replacement, an
    /// mremap source, the OOM reaper.
    Unmap,
    /// Pages in the range lost their translation or frame while the mapping
    /// stays: truncate zap, MADV_DONTNEED, guard install, COW break,
    /// swap-out, lazy-free discard.
    Clear,
    /// The range's access was reduced (READ or WRITE removed).
    ProtectionVma,
    /// A resident page now translates to a different frame with the same
    /// contents.
    Migrate,
    /// The address space is being torn down. This is the interval's final
    /// event: it is removed from the registry and
    /// [`MmuInterval::is_released`] becomes true.
    Release,
}

/// The invalidated range, in the address space the interval was registered
/// on. `start..end` is the operation's range and may extend past the
/// interval.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MmuNotifierRange {
    pub address_space_id: u64,
    pub start: u64,
    pub end: u64,
    pub event: MmuNotifierEvent,
}

impl MmuNotifierRange {
    /// Linux `mmu_notifier_range_blockable`. Always `false`: callbacks run
    /// under the address space's IRQ-masked mapping locks.
    pub const fn blockable(&self) -> bool {
        false
    }
}

/// A consumer of interval invalidations (Linux
/// `struct mmu_interval_notifier_ops`).
pub trait MmuIntervalNotifierOps: Send + Sync {
    /// Called once per firing operation that overlaps `interval`, after the
    /// registry has stored `cur_seq` in it. See the module documentation for
    /// the locks held and what the callback must not do.
    fn invalidate(&self, interval: &MmuInterval, range: &MmuNotifierRange, cur_seq: u64);
}

/// Errors from [`MmuIntervalNotifier::insert`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MmuNotifierError {
    /// Empty, overflowing, or beyond the user half.
    InvalidRange,
    /// The registry could not grow, or the address space already has
    /// [`MAX_INTERVALS_PER_SPACE`] intervals.
    OutOfMemory,
}

/// Bound on one address space's intervals. A firing site scans the
/// overlapping part of its own space's intervals with interrupts masked, so
/// the bound caps that scan; other address spaces locate (or skip) their own
/// run in logarithmic time. Linux has no fixed bound (its interval tree is
/// charged to memory).
pub const MAX_INTERVALS_PER_SPACE: usize = 16384;

/// One registered interval (Linux `struct mmu_interval_notifier`). Shared
/// between its owning [`MmuIntervalNotifier`] and the registry.
pub struct MmuInterval {
    address_space_id: u64,
    start: u64,
    end: u64,
    /// Linux `invalidate_seq`. Zero at insert; every invalidation stores a
    /// fresh odd value, so a sequence read before an invalidation never
    /// equals one stored by it.
    seq: AtomicU64,
    released: AtomicBool,
    ops: Arc<dyn MmuIntervalNotifierOps>,
}

impl core::fmt::Debug for MmuInterval {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MmuInterval")
            .field("address_space_id", &self.address_space_id)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("seq", &self.seq.load(Ordering::Relaxed))
            .field("released", &self.released.load(Ordering::Relaxed))
            .finish()
    }
}

impl MmuInterval {
    /// Stable identity of the address space this interval watches.
    pub fn address_space_id(&self) -> u64 {
        self.address_space_id
    }

    /// First byte of the interval.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// One past the last byte of the interval.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// Linux `mmu_interval_read_begin`: the sequence to pass to
    /// [`Self::read_retry`] after collecting the range's pages.
    pub fn read_begin(&self) -> u64 {
        self.seq.load(Ordering::Acquire)
    }

    /// Linux `mmu_interval_read_retry`: true if an invalidation fired since
    /// `seq` was read, so pages collected after `read_begin` are stale.
    /// Consumers call it under the lock their callback takes, immediately
    /// before publishing the pages to the device.
    pub fn read_retry(&self, seq: u64) -> bool {
        self.seq.load(Ordering::Acquire) != seq
    }

    /// Linux `mmu_interval_check_retry`: the advisory, lock-free form of
    /// [`Self::read_retry`].
    pub fn check_retry(&self, seq: u64) -> bool {
        self.seq.load(Ordering::Relaxed) != seq
    }

    /// Linux `mmu_interval_set_seq`. The registry already stores `cur_seq`
    /// before calling the callback; a Linux-shaped consumer may store it
    /// again under its own lock. Idempotent.
    pub fn set_seq(&self, cur_seq: u64) {
        self.seq.store(cur_seq, Ordering::Release);
    }

    /// True once the address space was torn down (exit, exec replacement,
    /// final drop). The range can never be collected again; Linux reports
    /// this as `-EFAULT` from `mmget_not_zero`.
    pub fn is_released(&self) -> bool {
        self.released.load(Ordering::Acquire)
    }

    /// Registry order: by address space, then start.
    fn key(&self) -> (u64, u64) {
        (self.address_space_id, self.start)
    }
}

/// Owning registration (Linux `mmu_interval_notifier_insert` until
/// `mmu_interval_notifier_remove`). Dropping it removes the interval; once
/// the drop returns no callback for it is running or will run.
pub struct MmuIntervalNotifier {
    interval: Arc<MmuInterval>,
}

impl core::fmt::Debug for MmuIntervalNotifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.interval.fmt(f)
    }
}

impl core::ops::Deref for MmuIntervalNotifier {
    type Target = MmuInterval;
    fn deref(&self) -> &MmuInterval {
        &self.interval
    }
}

impl MmuIntervalNotifier {
    /// Register `[start, start + length)` of `space`. Call before collecting
    /// any page of the range: only pages collected after this returns, inside
    /// a `read_begin`/`read_retry` section, are covered.
    ///
    /// Must not be called from an invalidation callback or under any
    /// address-space lock.
    pub fn insert(
        space: &AddressSpace,
        start: u64,
        length: u64,
        ops: Arc<dyn MmuIntervalNotifierOps>,
    ) -> Result<Self, MmuNotifierError> {
        let end = start
            .checked_add(length)
            .filter(|end| length != 0 && *end <= AddressSpace::USER_HALF_END)
            .ok_or(MmuNotifierError::InvalidRange)?;
        let interval = Arc::new(MmuInterval {
            address_space_id: space.identity(),
            start,
            end,
            seq: AtomicU64::new(0),
            released: AtomicBool::new(false),
            ops,
        });
        registry_insert(&interval)?;
        Ok(Self { interval })
    }

    /// The shared interval, for consumers that keep it beside other state.
    pub fn interval(&self) -> &MmuInterval {
        &self.interval
    }
}

impl Drop for MmuIntervalNotifier {
    fn drop(&mut self) {
        let id = self.interval.address_space_id;
        let removed = {
            let mut intervals = REGISTRY[shard_index(id)].intervals.lock();
            let (first, last) = space_run(&intervals, id);
            let position = intervals[first..last]
                .iter()
                .position(|candidate| Arc::ptr_eq(candidate, &self.interval));
            position.map(|offset| {
                LIVE.fetch_sub(1, Ordering::AcqRel);
                // Shifts within the existing buffer; never allocates.
                intervals.remove(first + offset)
            })
        };
        // The owner still holds `self.interval`, so this is never the last
        // reference and runs no consumer destructor; drop it unlocked anyway.
        drop(removed);
    }
}

const REGISTRY_SHARDS: usize = 64;

#[repr(align(64))]
struct Shard {
    /// Intervals of every address space whose identity selects this shard,
    /// sorted by [`MmuInterval::key`].
    intervals: IrqSafeSpinLock<Vec<Arc<MmuInterval>>>,
}

/// `[first, last)` of `address_space_id`'s intervals in a sorted shard.
fn space_run(intervals: &[Arc<MmuInterval>], address_space_id: u64) -> (usize, usize) {
    let first = intervals.partition_point(|i| i.address_space_id < address_space_id);
    let last = intervals.partition_point(|i| i.address_space_id <= address_space_id);
    (first, last)
}

static REGISTRY: [Shard; REGISTRY_SHARDS] = [const {
    Shard {
        intervals: IrqSafeSpinLock::new(Vec::new()),
    }
}; REGISTRY_SHARDS];

/// Registered intervals across all shards. Zero lets every firing site
/// return after one load, so address spaces without device mirrors pay
/// nothing.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// Source of invalidation sequences: odd, increasing, never zero.
static NEXT_SEQ: AtomicU64 = AtomicU64::new(1);

#[inline]
fn shard_index(address_space_id: u64) -> usize {
    address_space_id as usize & (REGISTRY_SHARDS - 1)
}

/// Insert in key order without allocating under the IRQ-masked shard lock:
/// grow into a replacement vector allocated with interrupts enabled, then
/// swap it in.
fn registry_insert(interval: &Arc<MmuInterval>) -> Result<(), MmuNotifierError> {
    let id = interval.address_space_id;
    let shard = &REGISTRY[shard_index(id)];
    let mut spare: Option<Vec<Arc<MmuInterval>>> = None;
    loop {
        let (needed, retired) = {
            let mut intervals = shard.intervals.lock();
            let (first, last) = space_run(&intervals, id);
            if last - first >= MAX_INTERVALS_PER_SPACE {
                return Err(MmuNotifierError::OutOfMemory);
            }
            let at = intervals.partition_point(|i| i.key() <= interval.key());
            if intervals.len() < intervals.capacity() {
                // Shifts within the existing buffer; never allocates.
                intervals.insert(at, interval.clone());
                LIVE.fetch_add(1, Ordering::AcqRel);
                return Ok(());
            }
            let needed = intervals.len() + 1;
            if let Some(mut bigger) = spare.take_if(|bigger| bigger.capacity() >= needed) {
                // Moves only: the capacity was reserved before locking.
                bigger.extend(intervals.drain(..at));
                bigger.push(interval.clone());
                bigger.extend(intervals.drain(..));
                LIVE.fetch_add(1, Ordering::AcqRel);
                (0, Some(core::mem::replace(&mut *intervals, bigger)))
            } else {
                (needed, None)
            }
        };
        if needed == 0 {
            // The retired buffer is freed with interrupts enabled.
            drop(retired);
            return Ok(());
        }
        let mut bigger = Vec::new();
        bigger
            .try_reserve_exact(needed.max(4).saturating_mul(2))
            .map_err(|_| MmuNotifierError::OutOfMemory)?;
        // Any smaller spare from a lost race is freed here, unlocked.
        spare = Some(bigger);
    }
}

/// Whether any interval is registered. Firing sites test this first, so
/// address spaces without device mirrors pay one load.
#[inline]
pub(crate) fn active() -> bool {
    LIVE.load(Ordering::Acquire) != 0
}

/// Fire every interval of `address_space_id` overlapping `[start, end)`.
/// Called by address-space operations with their mapping lock held; see the
/// module documentation for the sites and the lock order.
#[cold]
pub(crate) fn invalidate_range(
    address_space_id: u64,
    start: u64,
    end: u64,
    event: MmuNotifierEvent,
) {
    if start >= end {
        return;
    }
    let intervals = REGISTRY[shard_index(address_space_id)].intervals.lock();
    let (first, last) = space_run(&intervals, address_space_id);
    // Intervals starting at or past `end` cannot overlap; the rest of the
    // run is bounded by MAX_INTERVALS_PER_SPACE.
    let candidates = &intervals[first..last];
    let below_end = candidates.partition_point(|i| i.start < end);
    let range = MmuNotifierRange {
        address_space_id,
        start,
        end,
        event,
    };
    let mut cur_seq = 0;
    for interval in candidates[..below_end].iter().filter(|i| i.end > start) {
        if cur_seq == 0 {
            cur_seq = NEXT_SEQ.fetch_add(2, Ordering::Relaxed);
        }
        interval.seq.store(cur_seq, Ordering::Release);
        interval.ops.invalidate(interval, &range, cur_seq);
    }
}

/// Linux `mmu_notifier_release` for interval notifiers: fire `Release` on
/// every interval of the address space, mark them released and remove them
/// from the registry. Idempotent. Callers fire it before any frame of the
/// address space is released.
#[cold]
pub(crate) fn release_address_space(address_space_id: u64) {
    let mut intervals = REGISTRY[shard_index(address_space_id)].intervals.lock();
    let (first, last) = space_run(&intervals, address_space_id);
    if first == last {
        return;
    }
    let cur_seq = NEXT_SEQ.fetch_add(2, Ordering::Relaxed);
    for interval in &intervals[first..last] {
        interval.released.store(true, Ordering::Release);
        interval.seq.store(cur_seq, Ordering::Release);
        let range = MmuNotifierRange {
            address_space_id,
            start: interval.start,
            end: interval.end,
            event: MmuNotifierEvent::Release,
        };
        interval.ops.invalidate(interval, &range, cur_seq);
    }
    LIVE.fetch_sub(last - first, Ordering::AcqRel);
    // Each owning MmuIntervalNotifier still holds its Arc (its Drop removes
    // the interval under this lock), so the drain drops no last reference
    // and, shifting within the buffer, never allocates.
    intervals.drain(first..last);
}

/// Registered intervals on every address space, for tests that must prove
/// they leave the registry as they found it.
pub fn registered_intervals() -> usize {
    LIVE.load(Ordering::Acquire)
}
