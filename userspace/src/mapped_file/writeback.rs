//! Writeback of dirty generic-fallback `MAP_SHARED` pages — the flusher.
//!
//! A store through a `MAP_SHARED` file mapping changes a page of the file
//! cache and nothing else. Linux leaves it there: `munmap`, `exit_mmap` and
//! the old image of an `execve` only move the PTE dirty bit onto the folio
//! (`zap_pte_range` → `folio_mark_dirty`), and the data reaches the file
//! later, from somebody whose job that is —
//!
//! * the flusher (`wb_workfn` → `wb_writeback`), every
//!   `dirty_writeback_centisecs` (5 s), for pages dirty longer than
//!   `dirty_expire_centisecs` (30 s);
//! * `msync(MS_SYNC)`, `fsync`, `fdatasync`, `sync`, `syncfs`, an unmount;
//! * a dirtier that has outrun the flusher and is made to wait for it
//!   (`balance_dirty_pages`).
//!
//! NARF used to write at the unmap instead, synchronously, in whatever
//! context dropped the last reference to the address space. For an exiting
//! or killed process that is the executor thread: no current task to park,
//! the next task's slot already off the run queue. Every dirty page of every
//! file the space had mapped was written from there, one filesystem
//! operation per page, with the CPU spinning between polls and the task it
//! was about to run held hostage — and a `fork` child inherits its parent's
//! mappings, so every `fork`+`exec` paid for the parent's dirty pages again.
//!
//! This module is the somebody whose job it is.
//!
//! # Ownership
//!
//! A dirty page belongs to its FILE. Each file with a mapped or unwritten
//! page has one [`CachedFile`] entry in the cache, and the entry holds the
//! file open. So the last unmap, the last `close` and the death of every
//! process that ever mapped the file leave the page where it is, listed as
//! idle-dirty, and somebody can still write it. The entry goes away when the
//! file has no mapped and no unwritten page left.
//!
//! # One batch
//!
//! Every path that writes — the background task, `fsync`, `msync`, `sync` —
//! runs the same engine, [`write_range`], one batch at a time:
//!
//! 1. take the file's writeback lock;
//! 2. under the cache lock, pin up to [`BATCH_PAGES`] candidate pages
//!    (`wb_pins`, Linux `PG_writeback`) and take a reference to each one's
//!    clean image — no bytes are compared or copied under that lock;
//! 3. with the cache lock released, compare each pinned page with its clean
//!    image and copy the dirty ones into a private buffer, joining
//!    neighbours into one run;
//! 4. write each run with ONE filesystem operation, clamped to the file's
//!    current size;
//! 5. under the cache lock, make the bytes that were WRITTEN each page's new
//!    clean image, and unpin.
//!
//! Step 5 never looks at the page again. A store that lands in the page
//! after step 3 is not in the buffer and therefore not in the new clean
//! image: the page still differs from it and the next pass writes it. Taking
//! the page's bytes at completion time instead would mark that store clean
//! without ever writing it.
//!
//! # Ordering against everything else that changes the file
//!
//! * `ftruncate`, `truncate`, `O_TRUNC` and `fallocate` take the same
//!   per-file lock around the filesystem operation and the cache
//!   invalidation that follows it ([`size_change_serialized`]). A batch
//!   therefore either completes before the size change starts — Linux
//!   `truncate_inode_pages_range` waits for writeback the same way — or
//!   starts after the invalidation has removed the pages. It can neither
//!   write a page the truncate has discarded nor extend the file again.
//! * `write(2)` does not take that lock. It samples [`write_stamp`] before
//!   it writes and hands the stamp to [`super::note_file_written`], which
//!   uses it to tell whether a batch could have written the same page in
//!   between; if so the page is left dirty and is written again.
//!
//! # What is NOT here (LINUX-GAP)
//!
//! Dirtiness is found by comparing a page with a stored copy of what the
//! file holds, because nothing records the store itself. That costs a 4 KiB
//! compare for every mapped page the sweep visits and a second copy of every
//! cached page. The long-term shape is Linux's: take dirtiness from the page
//! tables — harvest the PTE dirty bit in the writeback task, or map shared
//! file pages read-only and take the first write fault
//! (`page_mkwrite` / `folio_mark_dirty`) — so a clean mapped page costs
//! nothing and the clean copy goes away. `userspace/specification/spec.md`
//! records it.

use super::{
    shared_file_identity, FileSlot, SharedFileIdentity, SharedFileKey, SharedFilePage,
    SharedFilePages, SHARED_FILE_PAGES,
};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use narf_filesystem::{FileOps, FsError};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

/// Pages one batch pins, and so the most one filesystem operation writes:
/// 1 MiB.
///
/// The larger the better for the file — on a copy-on-write filesystem each
/// operation becomes one extent, and a file written back a page at a time
/// ends up with an extent per page, which every later overwrite then has to
/// walk. The size of the write is also most of its speed: measured on this
/// kernel's btrfs, sequential 4 KiB writes ran at 7 MiB/s and 128 KiB
/// writes at 222 MiB/s. The bound is what a batch costs everyone else: for
/// its duration the filesystem's own lock is held and the CPU does not
/// reschedule (the write completes inside one poll), and the batch's
/// private copy and new clean images are both this size. A megabyte is a
/// few milliseconds at the large-write rate, and under a tenth of a second
/// even at the 10–15 MiB/s seen on a badly fragmented file — the most a
/// queued task or another writer then waits for.
///
/// Pages are taken in ascending file offset — the cache's by-file index
/// and the idle-dirty list are both ordered that way — so a file's runs
/// reach the filesystem low to high. Nothing here walks the cache by
/// physical frame: a filesystem that receives a file's extents in
/// shuffled order may split its metadata leaves far more often.
///
/// Only dirty neighbours are joined. A clean page between two dirty runs is
/// NOT written to bridge them, for two reasons. The clean image is the last
/// content the cache saw the file have, not a guarantee of what the file
/// has now — a write the cache was never told about leaves it stale, and
/// today that costs nothing because clean pages are never written; writing
/// them would put the stale bytes over the newer ones. And it would not pay
/// even if it were safe: on a fresh file one more operation costs about
/// what writing one more page does, so a bridged gap of a single page
/// already breaks even, and on a copy-on-write filesystem every bridged
/// page is unchanged data given a new extent.
pub(crate) const BATCH_PAGES: usize = 256;

/// Cache entries one cache-lock hold may step over while looking for pages
/// to pin. Selection compares nothing, so this bounds a hold to a short
/// index walk.
const SCAN_PER_HOLD: usize = 256;

/// Mapped pages the background sweep examines per pass (64 MiB of compares,
/// spread over [`BATCH_PAGES`]-sized steps with a yield between each). The
/// sweep resumes where it stopped, so a cache larger than this is covered
/// over several passes.
const SWEEP_PAGES_PER_PASS: usize = 16 * 1024;

/// Linux `dirty_writeback_centisecs`: how often the flusher wakes.
const WRITEBACK_INTERVAL_MS: u64 = 5_000;

/// Linux `dirty_expire_centisecs`: how long a page that is still mapped may
/// stay dirty before the flusher writes it. A page nobody maps any more is
/// written on the next pass — it can change no further, and it is memory the
/// cache cannot give back until it is clean.
const DIRTY_EXPIRE_MS: u64 = 30_000;

/// Background passes a file's writes may fail in a row before its unmapped
/// dirty pages are dropped. A filesystem that keeps refusing — a volume
/// that went read-only, a device that is gone — must not pin its pages and
/// its file for ever.
/// Passes running an unmapped page must be found owing only bytes past EOF
/// before it is let go.
const MAX_FAILED_PASSES: u32 = 3;

/// `u64::MAX`: use [`DIRTY_EXPIRE_MS`]. Tests shorten it.
static DIRTY_EXPIRE_OVERRIDE_MS: AtomicU64 = AtomicU64::new(u64::MAX);

fn dirty_expire_ms() -> u64 {
    match DIRTY_EXPIRE_OVERRIDE_MS.load(Ordering::Relaxed) {
        u64::MAX => DIRTY_EXPIRE_MS,
        ms => ms,
    }
}

/// Pages evicted from the idle-clean list, and page-content comparisons
/// made — by writeback and by the read overlay, the only code that makes
/// any. Kernel tests read both to show that a fault, an unmap and a
/// publication do work that does not grow with the cache.
pub(super) static EVICTIONS: AtomicU64 = AtomicU64::new(0);
pub(super) static PAGE_COMPARES: AtomicU64 = AtomicU64::new(0);

/// Unmapped pages that may hold bytes their file does not have yet. This
/// is the memory writeback owes back, and what [`throttle_dirtier`] bounds.
pub(super) static IDLE_DIRTY_PAGES: AtomicUsize = AtomicUsize::new(0);

static FILE_ENTRIES: AtomicUsize = AtomicUsize::new(0);

const FILTER_BUCKETS: usize = 1024;

/// Counting filter over the files that have an entry. A read of a file
/// nobody maps — nearly every read — is turned away here without touching
/// the cache lock.
static FILTER: [AtomicU32; FILTER_BUCKETS] = [const { AtomicU32::new(0) }; FILTER_BUCKETS];

/// Keyed on the backing anchor alone, so a caller can ask before computing
/// the full identity: that needs `inode_attrs()`, which on btrfs takes the
/// inode's lock and copies it — per `read(2)`, for every file read.
fn anchor_bucket(anchor: usize) -> &'static AtomicU32 {
    let mixed = (anchor as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    &FILTER[(mixed >> 54) as usize % FILTER_BUCKETS]
}

fn filter_bucket(identity: SharedFileIdentity) -> &'static AtomicU32 {
    anchor_bucket(identity.anchor)
}

/// Calls of [`entry_identity`] that got past the lock-free checks and
/// computed a file's full identity. Kernel tests read it.
pub(super) static IDENTITY_LOOKUPS: AtomicU64 = AtomicU64::new(0);

/// `ops`'s identity, if its file may have a cache entry. For a file that
/// has none — nearly every file — this is two atomic loads and a pointer
/// read, and nothing else: no lock, no `inode_attrs()`, no allocation.
fn entry_identity(ops: &dyn FileOps) -> Option<SharedFileIdentity> {
    if FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return None;
    }
    if anchor_bucket(ops.mmap_backing_identity()).load(Ordering::Acquire) == 0 {
        return None;
    }
    IDENTITY_LOOKUPS.fetch_add(1, Ordering::Relaxed);
    let identity = shared_file_identity(ops);
    may_have_entry(identity).then_some(identity)
}

/// Called with the cache lock held, when an entry is inserted.
pub(super) fn filter_add(identity: SharedFileIdentity) {
    filter_bucket(identity).fetch_add(1, Ordering::AcqRel);
    FILE_ENTRIES.fetch_add(1, Ordering::AcqRel);
}

/// Called with the cache lock held, when an entry is removed.
pub(super) fn filter_remove(identity: SharedFileIdentity) {
    filter_bucket(identity).fetch_sub(1, Ordering::AcqRel);
    FILE_ENTRIES.fetch_sub(1, Ordering::AcqRel);
}

fn may_have_entry(identity: SharedFileIdentity) -> bool {
    filter_bucket(identity).load(Ordering::Acquire) != 0
}

/// One file's writeback state. Shared by the cache's entry for the file and
/// by whoever is writing or resizing it right now.
pub(super) struct CachedFile {
    identity: SharedFileIdentity,
    /// Held for one batch (pin → write → mark clean), and around a size
    /// change and the invalidation that follows it. Linux splits this
    /// between the folio lock, `PG_writeback` and `invalidate_lock`.
    lock: FairLock,
    /// A background write failure nobody has been told about. Reported once,
    /// by the next `fsync`/`msync` of the file (Linux `errseq_t` in
    /// `address_space::wb_err`, without its per-open cursor: here the first
    /// caller to ask is the one that sees it).
    error: IrqSafeSpinLock<Option<FsError>>,
    failed_passes: AtomicU32,
    /// Background passes still to skip after a transient failure.
    skip_passes: AtomicU32,
}

impl CachedFile {
    pub(super) fn new(identity: SharedFileIdentity) -> Arc<Self> {
        Arc::new(Self {
            identity,
            lock: FairLock::new(),
            error: IrqSafeSpinLock::new(None),
            failed_passes: AtomicU32::new(0),
            skip_passes: AtomicU32::new(0),
        })
    }

    fn record_error(&self, error: FsError) {
        *self.error.lock() = Some(error);
    }

    fn take_error(&self) -> Option<FsError> {
        self.error.lock().take()
    }

    fn has_error(&self) -> bool {
        self.error.lock().is_some()
    }
}

/// The per-file writeback lock: a mutex that hands itself to the waiter at
/// the head of its queue on release, instead of freeing itself for whoever
/// polls first (`narf_lib::mutex::Mutex` does the latter, and a woken
/// waiter that loses the race goes to the back of the queue). With sixteen
/// threads dirtying a mapping and writing the file, an `msync` that queues
/// for each of its batches and an `ftruncate` that queues once were passed
/// over again and again: a soak saw `msync` blocked for over 200 s. Here a
/// waiter is served in arrival order, so a sync or a size change waits for
/// at most the holders queued before it — Linux's `filemap_write_and_wait`
/// likewise never waits on writers that arrive after it.
pub(super) struct FairLock {
    state: IrqSafeSpinLock<FairState>,
}

struct FairState {
    held: bool,
    /// Waiters in arrival order: ticket and the waker to call.
    queue: alloc::collections::VecDeque<(u64, Option<Waker>)>,
    /// Ticket the lock was handed to and not yet claimed, if any.
    granted: Option<u64>,
    next_ticket: u64,
}

impl FairLock {
    fn new() -> Self {
        Self {
            state: IrqSafeSpinLock::new(FairState {
                held: false,
                queue: alloc::collections::VecDeque::new(),
                granted: None,
                next_ticket: 0,
            }),
        }
    }

    pub(super) fn lock(&self) -> FairLockFuture<'_> {
        FairLockFuture {
            lock: self,
            ticket: None,
        }
    }

    /// Only when free and nobody is queued: never jumps the queue.
    #[cfg(feature = "kernel-test")]
    pub(super) fn try_lock(&self) -> Option<FairGuard<'_>> {
        let mut state = self.state.lock();
        if state.held || !state.queue.is_empty() || state.granted.is_some() {
            return None;
        }
        state.held = true;
        Some(FairGuard { lock: self })
    }

    /// Hand the lock to the next waiter, or free it. Called with `state`
    /// locked; returns the waker to call once it is released.
    fn pass_on(state: &mut FairState) -> Option<Waker> {
        match state.queue.pop_front() {
            Some((ticket, waker)) => {
                state.granted = Some(ticket);
                waker
            }
            None => {
                state.held = false;
                None
            }
        }
    }
}

pub(super) struct FairLockFuture<'a> {
    lock: &'a FairLock,
    ticket: Option<u64>,
}

impl<'a> Future for FairLockFuture<'a> {
    type Output = FairGuard<'a>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<FairGuard<'a>> {
        let this = self.get_mut();
        let mut state = this.lock.state.lock();
        match this.ticket {
            None => {
                if !state.held && state.queue.is_empty() && state.granted.is_none() {
                    state.held = true;
                    return Poll::Ready(FairGuard { lock: this.lock });
                }
                let ticket = state.next_ticket;
                state.next_ticket += 1;
                state.queue.push_back((ticket, Some(cx.waker().clone())));
                this.ticket = Some(ticket);
                Poll::Pending
            }
            Some(ticket) => {
                if state.granted == Some(ticket) {
                    state.granted = None;
                    this.ticket = None;
                    return Poll::Ready(FairGuard { lock: this.lock });
                }
                if let Some(entry) = state.queue.iter_mut().find(|(t, _)| *t == ticket) {
                    entry.1 = Some(cx.waker().clone());
                }
                Poll::Pending
            }
        }
    }
}

impl Drop for FairLockFuture<'_> {
    fn drop(&mut self) {
        let Some(ticket) = self.ticket else {
            return;
        };
        let wake = {
            let mut state = self.lock.state.lock();
            if state.granted == Some(ticket) {
                // Handed to us and never claimed: pass it on.
                state.granted = None;
                FairLock::pass_on(&mut state)
            } else {
                state.queue.retain(|(t, _)| *t != ticket);
                None
            }
        };
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

pub(super) struct FairGuard<'a> {
    lock: &'a FairLock,
}

impl Drop for FairGuard<'_> {
    fn drop(&mut self) {
        let wake = FairLock::pass_on(&mut self.lock.state.lock());
        if let Some(waker) = wake {
            waker.wake();
        }
    }
}

static WRITEBACK_SEQ: AtomicU64 = AtomicU64::new(0);

/// Stamps of the writes now in flight outside the file lock, by value.
/// [`WRITEBACK_SEQ`] moves only with this lock held, so a stamp is either
/// registered before a batch completes or sees that batch's number.
/// Lock order: cache lock, then this one.
static IN_FLIGHT: IrqSafeSpinLock<BTreeMap<u64, usize>> = IrqSafeSpinLock::new(BTreeMap::new());

/// Where writeback stood when a kernel read began: see [`overlay_dirty`].
#[derive(Copy, Clone)]
pub(crate) struct ReadEpoch(u64);

/// Sample before a filesystem read whose result goes through
/// [`overlay_dirty`].
pub(crate) fn read_epoch() -> ReadEpoch {
    ReadEpoch(WRITEBACK_SEQ.load(Ordering::Acquire))
}

/// "No writeback batch has completed since" — taken by a write that runs
/// outside the file's writeback lock (AIO, the `copy_file_range` fallback,
/// a splice/sendfile sink) before it writes, and handed to
/// [`super::note_file_written`] after. While it is alive, a batch that
/// completes keeps the pages it wrote listed instead of settling them: the
/// write may yet have to tell such a page that the batch put older bytes
/// on the file after it ([`settle_allowed`]). A guard newer than a page's
/// last batch does not hold that page, so a writer that never pauses
/// cannot keep pages unsettled for ever.
pub(crate) struct WriteStamp {
    pub(super) seq: u64,
    registered: bool,
}

pub(crate) fn write_stamp() -> WriteStamp {
    let mut in_flight = IN_FLIGHT.lock();
    let seq = WRITEBACK_SEQ.load(Ordering::Acquire);
    *in_flight.entry(seq).or_insert(0) += 1;
    WriteStamp {
        seq,
        registered: true,
    }
}

impl WriteStamp {
    /// For a write made under the file's writeback lock: no batch of this
    /// file can run between the write and its report, so the report always
    /// settles the bytes and holds no other page back.
    fn locked() -> Self {
        Self {
            seq: u64::MAX,
            registered: false,
        }
    }
}

impl Drop for WriteStamp {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        let mut in_flight = IN_FLIGHT.lock();
        if let Some(count) = in_flight.get_mut(&self.seq) {
            *count -= 1;
            if *count == 0 {
                in_flight.remove(&self.seq);
            }
        }
    }
}

/// A page last written by batch `wb_seq` may be settled — called clean,
/// listed for reuse or freed — only when no out-of-lock write that began
/// before that batch completed is still in flight.
fn settle_allowed(oldest_in_flight: Option<u64>, wb_seq: u64) -> bool {
    oldest_in_flight.is_none_or(|oldest| oldest >= wb_seq)
}

/// Which pages a batch takes.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Select {
    /// `fsync`, `msync`, `sync`: every dirty page in the range, now.
    All,
    /// Background: pages nobody maps.
    Idle,
    /// Background: mapped pages that have been dirty for
    /// [`DIRTY_EXPIRE_MS`].
    Aged,
}

enum Action {
    /// Nothing to write.
    Clean,
    /// Dirty, mapped, and not due yet: remember when it will be.
    Defer(narf_time::Deadline),
    /// Copied into a run, at `at..at + len` of the run's buffer.
    Queued { run: usize, at: usize, len: usize },
    /// The run reached the file: this is the page's new clean image.
    Written(Arc<Vec<u8>>),
    /// Everything the page still owes lies past EOF — the whole page, or
    /// the part of it that differs from its clean image. Those bytes are
    /// not file data and are never written; an unmapped page in this state
    /// for [`MAX_FAILED_PASSES`] passes running is let go. Not at once: the
    /// size a filesystem reports can lag a write that has just extended the
    /// file, and one stale answer must not cost a page its data.
    PastEof,
    /// The write failed with an error worth retrying, or there was no
    /// memory to do it. The page stays dirty.
    Failed,
}

/// Errors after which a page stays dirty and is retried (Linux
/// `redirty_page_for_writepage` on `-ENOSPC`, `-EDQUOT`, `-ENOMEM`,
/// `-EAGAIN`). Any other write error is hard: it is recorded for the next
/// `fsync` and the page is marked clean with the bytes that were attempted,
/// as btrfs `extent_writepage` leaves a folio after `-EIO` — writeback over,
/// dirty bit already cleared by `folio_clear_dirty_for_io`, the error set on
/// the mapping, the data still in the page cache.
fn transient(error: FsError) -> bool {
    matches!(
        error,
        FsError::NoSpace | FsError::QuotaExceeded | FsError::OutOfMemory | FsError::WouldBlock
    )
}

struct Pinned {
    offset: u64,
    phys: PhysAddr,
    clean: Arc<Vec<u8>>,
    /// No mapping and no pending publication when it was pinned.
    idle: bool,
    due: Option<narf_time::Deadline>,
    action: Action,
}

struct Run {
    offset: u64,
    buf: Vec<u8>,
}

fn key(identity: SharedFileIdentity, offset: u64) -> SharedFileKey {
    SharedFilePages::key(identity, offset)
}

/// Take a writeback hold on `page`. Called with the cache lock held and the
/// file's writeback lock held, so one batch at a time holds a given page.
fn pin(page: &mut SharedFilePage, batch: &mut Vec<Pinned>) {
    page.wb_pins += 1;
    page.redirtied = false;
    batch.push(Pinned {
        offset: page.offset,
        phys: page.phys,
        clean: Arc::clone(&page.clean),
        idle: page.mappings == 0 && page.pending == 0,
        due: page.write_due,
        action: Action::Clean,
    });
}

/// Step 2 of a batch. Returns the pinned pages, where to resume (`None`:
/// the range is exhausted) and how many entries were stepped over.
fn pin_batch(
    mut batch: Vec<Pinned>,
    identity: SharedFileIdentity,
    from: u64,
    end: u64,
    select: Select,
    scan: usize,
) -> (Vec<Pinned>, Option<u64>, usize) {
    debug_assert!(batch.capacity() >= BATCH_PAGES && batch.is_empty());
    let mut next = None;
    let mut examined = 0usize;
    let mut pages = SHARED_FILE_PAGES.lock();
    let SharedFilePages {
        by_phys,
        by_file,
        idle_dirty,
        ..
    } = &mut *pages;
    match select {
        Select::Idle => {
            for listed in idle_dirty.range(key(identity, from)..) {
                if listed.file != identity || listed.offset >= end {
                    break;
                }
                if batch.len() == BATCH_PAGES {
                    next = Some(listed.offset);
                    break;
                }
                examined += 1;
                let Some(page) = by_file.get(listed).and_then(|phys| by_phys.get_mut(phys)) else {
                    continue;
                };
                pin(page, &mut batch);
            }
        }
        Select::All | Select::Aged => {
            for (cached, phys) in by_file.range(key(identity, from)..) {
                if cached.file != identity || cached.offset >= end {
                    break;
                }
                if batch.len() == BATCH_PAGES || examined == scan {
                    next = Some(cached.offset);
                    break;
                }
                examined += 1;
                let Some(page) = by_phys.get_mut(phys) else {
                    continue;
                };
                let held = page.mappings != 0 || page.pending != 0;
                // Recorded state picks the pages; nothing is compared here.
                // A mapped page no writable mapping has held cannot differ
                // from the file, and an unmapped page that is not listed
                // is clean.
                let wanted = if held {
                    page.maybe_dirty
                } else {
                    select == Select::All && page.idle_dirty
                };
                if wanted {
                    pin(page, &mut batch);
                }
            }
        }
    }
    (batch, next, examined)
}

/// Step 3 of a batch: decide each pinned page's fate against the file size
/// `size`, and copy the dirty ones into runs. Runs with no lock held.
///
/// `out_of_memory` is set when a dirty page could not be copied: it stays
/// dirty, and the caller must not report the range written.
fn examine(batch: &mut [Pinned], size: u64, select: Select, out_of_memory: &mut bool) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    if runs.try_reserve(batch.len()).is_err() {
        *out_of_memory = true;
        for page in batch.iter_mut() {
            page.action = Action::Failed;
        }
        return runs;
    }
    for page in batch.iter_mut() {
        if page.offset >= size {
            page.action = Action::PastEof;
            continue;
        }
        let len = (size - page.offset).min(4096) as usize;
        // SAFETY: the page is pinned, so its frame stays allocated until
        // `finish_batch` unpins it, and every frame is identity-mapped. A
        // mapping may be storing into the page while it is read: writeback
        // then captures either side of that store, and whichever it missed
        // leaves the page different from the image written, hence dirty.
        if len < 4096 {
            // The file's last page. What a mapping stored past EOF is not
            // file data: Linux zeroes the folio's tail on every writeback of
            // it (`folio_zero_segment` in `block_write_full_folio`), so the
            // bytes can never reach the file, even if it later grows over
            // them. Here the tail goes back to its clean image, which past
            // EOF is what the file reads there — zeros.
            // SAFETY: the page is pinned and identity-mapped (see the read
            // below); `len < 4096`.
            let tail = unsafe {
                core::slice::from_raw_parts_mut(
                    page.phys.kernel_mut_ptr::<u8>().add(len),
                    4096 - len,
                )
            };
            for (byte, clean) in tail.iter_mut().zip(&page.clean[len..]) {
                if *byte != *clean {
                    *byte = *clean;
                }
            }
        }
        // SAFETY: as described above the tail clearing: pinned until
        // `finish_batch`, identity-mapped, one whole page.
        let live = unsafe { core::slice::from_raw_parts(page.phys.kernel_ptr::<u8>(), 4096) };
        PAGE_COMPARES.fetch_add(1, Ordering::Relaxed);
        if live[..len] == page.clean[..len] {
            continue;
        }
        if select == Select::Aged {
            match page.due {
                Some(due) if due.expired() => {}
                Some(due) => {
                    page.action = Action::Defer(due);
                    continue;
                }
                None => {
                    page.action = Action::Defer(narf_time::Deadline::after_ms(dirty_expire_ms()));
                    continue;
                }
            }
        }
        // A short page is the file's last: nothing can follow it in a run.
        let joins = runs.last().is_some_and(|run| {
            run.buf.len() % 4096 == 0 && run.offset + run.buf.len() as u64 == page.offset
        });
        if !joins {
            runs.push(Run {
                offset: page.offset,
                buf: Vec::new(),
            });
        }
        let index = runs.len() - 1;
        let run = &mut runs[index];
        if run.buf.try_reserve(len).is_err() {
            *out_of_memory = true;
            page.action = Action::Failed;
            if run.buf.is_empty() {
                runs.pop();
            }
            continue;
        }
        let at = run.buf.len();
        run.buf.extend_from_slice(&live[..len]);
        page.action = Action::Queued {
            run: index,
            at,
            len,
        };
    }
    runs
}

async fn write_all(ops: &Arc<dyn FileOps>, offset: u64, bytes: &[u8]) -> Result<(), FsError> {
    let mut done = 0usize;
    while done < bytes.len() {
        match ops.write(offset + done as u64, &bytes[done..]).await? {
            0 => return Err(FsError::Io(narf_block::BlockError::IOError)),
            n => done += n.min(bytes.len() - done),
        }
    }
    Ok(())
}

/// Turn each queued page of a finished run into its outcome: the bytes that
/// were written become the page's clean image (past the written length the
/// old image stands — those bytes were not written).
fn settle_runs(batch: &mut [Pinned], runs: &[Run], results: &[Result<(), FsError>]) {
    for page in batch.iter_mut() {
        let Action::Queued { run, at, len } = page.action else {
            continue;
        };
        page.action = match results[run] {
            Err(error) if transient(error) => Action::Failed,
            // Written, or failed hard: either way what was attempted is the
            // page's clean image from now on.
            Ok(()) | Err(_) => {
                let mut image = Vec::new();
                if image.try_reserve_exact(4096).is_err() {
                    // With no memory to record it the page simply stays
                    // dirty and is written again.
                    Action::Failed
                } else {
                    image.extend_from_slice(&runs[run].buf[at..at + len]);
                    image.extend_from_slice(&page.clean[len..]);
                    Action::Written(Arc::new(image))
                }
            }
        };
    }
}

/// Step 5 of a batch: record what was written and release the pins.
/// Returns the number of pages written.
///
/// `free` and `garbage` were reserved before the batch pinned anything
/// ([`Reserved`]), so nothing here allocates.
fn finish_batch(
    batch: Vec<Pinned>,
    generation: Option<u64>,
    mut free: Vec<PhysAddr>,
    mut garbage: Vec<Arc<Vec<u8>>>,
) -> usize {
    let mut wrote = 0usize;
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        // Under the cache lock, and with the in-flight set's lock: a stamp
        // registered before this point sees these pages as written after
        // it began.
        let (seq, oldest_in_flight) = {
            let in_flight = IN_FLIGHT.lock();
            let seq = WRITEBACK_SEQ.fetch_add(1, Ordering::AcqRel) + 1;
            (seq, in_flight.keys().next().copied())
        };
        for pinned in batch {
            let Pinned {
                phys,
                clean,
                idle,
                action,
                ..
            } = pinned;
            garbage.push(clean);
            let (cached, release) = pages.unpin(phys.raw());
            if let Some(frame) = release {
                free.push(frame);
            }
            if !cached {
                // Invalidated while it was being written: a truncate or a
                // hole punch owns the outcome now.
                if let Action::Written(image) = action {
                    garbage.push(image);
                }
                continue;
            }
            let page = pages
                .by_phys
                .get_mut(&phys.raw())
                .expect("unpinned page is cached");
            let now_idle = page.mappings == 0 && page.pending == 0;
            // An unmapped page whose image went to the file, and which
            // nothing has touched since it was pinned, owes the file
            // nothing more. A page that was mapped at any point during the
            // batch may have been stored to after the copy; it is compared
            // again on the next pass.
            let untouched = idle && now_idle && !page.redirtied;
            let mut settled = false;
            let mut discard = false;
            if !matches!(action, Action::PastEof) {
                page.past_eof_passes = 0;
            }
            match action {
                Action::Written(image) => {
                    garbage.push(core::mem::replace(&mut page.clean, image));
                    page.wb_seq = seq;
                    page.cache_generation = generation;
                    page.write_due = None;
                    wrote += 1;
                    settled = untouched;
                }
                Action::Clean => {
                    if !now_idle {
                        page.write_due = None;
                    }
                    settled = untouched;
                }
                Action::Defer(due) => page.write_due = Some(due),
                Action::PastEof => {
                    page.past_eof_passes = page.past_eof_passes.saturating_add(1);
                    discard = untouched
                        && page.wb_pins == 0
                        && u32::from(page.past_eof_passes) >= MAX_FAILED_PASSES;
                }
                Action::Queued { .. } | Action::Failed => {}
            }
            // An out-of-lock write that began before this page's last batch
            // may still have to report that the batch overwrote it on the
            // file. Keep the page listed until it has.
            settled &= settle_allowed(oldest_in_flight, page.wb_seq);
            discard &= settle_allowed(oldest_in_flight, page.wb_seq);
            let retire =
                discard || (settled && page.wb_pins == 0 && page.cache_generation.is_none());
            if settled {
                // Compared (or written) with no mapping to change it since:
                // the one place a page becomes known clean again.
                page.maybe_dirty = false;
                pages.clear_idle_dirty(phys.raw());
            }
            if retire {
                if let Some(frame) = pages.retire_phys(phys.raw()) {
                    free.push(frame);
                }
            } else if settled {
                if let Some(frame) = pages.keep_idle_clean(phys.raw()) {
                    free.push(frame);
                }
            }
        }
    }
    drop(garbage);
    for frame in free {
        narf_memory::free_frame(narf_memory::PhysFrame::new(frame));
    }
    wrote
}

/// The pages one batch holds. However the batch ends — written, failed, or
/// its future dropped while a write was still pending — the pins come off
/// here, so a page can never be left looking as if it were under writeback
/// for ever (it could then be neither retired nor trusted by `write(2)`).
struct Batch {
    pages: Vec<Pinned>,
    reserved: Reserved,
}

/// Kernel tests: make the next reservations fail, as an exhausted allocator
/// would.
#[cfg(feature = "kernel-test")]
static FAIL_RESERVE: AtomicBool = AtomicBool::new(false);

/// Everything step 5 needs, reserved — fallibly — before a batch pins a
/// page: completing a batch must not fail, and failing to reserve must
/// leave nothing pinned.
#[derive(Default)]
struct Reserved {
    pages: Vec<Pinned>,
    /// Frames to free: a doomed page's last hold, a retired page, a page
    /// evicted to make room — at most three per page.
    free: Vec<PhysAddr>,
    /// Clean images dropped after the cache lock: the pinned one and the
    /// replaced one — at most two per page.
    garbage: Vec<Arc<Vec<u8>>>,
    results: Vec<Result<(), FsError>>,
}

impl Reserved {
    fn new() -> Result<Self, FsError> {
        #[cfg(feature = "kernel-test")]
        if FAIL_RESERVE.load(Ordering::Acquire) {
            return Err(FsError::OutOfMemory);
        }
        let mut reserved = Self::default();
        reserved
            .pages
            .try_reserve_exact(BATCH_PAGES)
            .and_then(|()| reserved.free.try_reserve_exact(3 * BATCH_PAGES))
            .and_then(|()| reserved.garbage.try_reserve_exact(2 * BATCH_PAGES))
            .and_then(|()| reserved.results.try_reserve_exact(BATCH_PAGES))
            .map_err(|_| FsError::OutOfMemory)?;
        Ok(reserved)
    }
}

impl Batch {
    /// Step 5: record what was written and unpin. Returns pages written.
    fn finish(mut self, generation: Option<u64>) -> usize {
        let pages = core::mem::take(&mut self.pages);
        let reserved = core::mem::take(&mut self.reserved);
        finish_batch(pages, generation, reserved.free, reserved.garbage)
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        if !self.pages.is_empty() {
            // Abandoned before its writes were accounted: nothing is marked
            // written, every queued page simply stays dirty.
            let pages = core::mem::take(&mut self.pages);
            let reserved = core::mem::take(&mut self.reserved);
            finish_batch(pages, None, reserved.free, reserved.garbage);
        }
    }
}

/// How a call of [`write_range`] goes about it.
#[derive(Copy, Clone)]
struct Plan {
    select: Select,
    /// The caller already holds the file's writeback lock.
    locked: bool,
    caller: Caller,
}

impl Plan {
    /// A syscall writing every dirty page: `fsync`, `msync`, `sync`.
    const SYNC: Self = Self {
        select: Select::All,
        locked: false,
        caller: Caller::Syscall,
    };

    /// The flusher, for one class of page.
    const fn background(select: Select) -> Self {
        Self {
            select,
            locked: false,
            caller: Caller::Task,
        }
    }
}

/// Where a call of [`write_range`] stopped.
struct Progress {
    wrote: usize,
    /// `Some(offset)`: the scan budget ran out before the range did.
    resume: Option<u64>,
}

/// Write the dirty cached pages of `file` in `[from, end)` that `select`
/// takes, one batch at a time.
///
/// One forward pass by file offset: every page in the range is looked at
/// once and written at most once per call, so a call's work is bounded by
/// the range, however fast other threads dirty it — a page stored to after
/// the pass went by is left for the next writeback, as Linux's
/// `tag_pages_for_writeback` leaves a folio redirtied after tagging.
///
/// `locked` says the caller already holds the file's writeback lock (a size
/// change flushing before it shifts the file's contents); otherwise each
/// batch takes and releases it. `budget` bounds the cache entries stepped
/// over.
///
/// Between batches — with the file lock released and no filesystem
/// operation in progress — there is a scheduling point
/// ([`scheduling_point`]), whoever is running the engine. A filesystem
/// write that completes inside one poll never parks its caller, so without
/// one an `fsync` of a few thousand dirty pages is one unbroken run in the
/// kernel and every task queued on that CPU waits for all of it.
///
/// The first failed write ends the call with its error. Every page pinned
/// by a batch is unpinned by that same batch, whatever happened to the
/// write ([`Batch`]).
async fn write_range(
    file: &Arc<CachedFile>,
    ops: &Arc<dyn FileOps>,
    (mut from, end): (u64, u64),
    plan: Plan,
    budget: &mut usize,
) -> Result<Progress, FsError> {
    let Plan {
        select,
        locked,
        caller,
    } = plan;
    let mut wrote = 0usize;
    loop {
        if *budget == 0 {
            return Ok(Progress {
                wrote,
                resume: Some(from),
            });
        }
        // Never `Ok` with pages unwritten: no memory to do the batch is
        // this call's error, and the pages stay dirty for a later pass.
        let mut reserved = Reserved::new()?;
        let guard = if locked {
            None
        } else {
            Some(file.lock.lock().await)
        };
        let (pages, next, examined) = pin_batch(
            core::mem::take(&mut reserved.pages),
            file.identity,
            from,
            end,
            select,
            (*budget).min(SCAN_PER_HOLD),
        );
        let mut results = core::mem::take(&mut reserved.results);
        let mut batch = Batch { pages, reserved };
        *budget = budget.saturating_sub(examined.max(1));
        // Sampled under the file lock: no truncate can move it before the
        // writes below, so a batch never writes past the size it saw.
        let size = ops.stat().size;
        let mut out_of_memory = false;
        let runs = examine(&mut batch.pages, size, select, &mut out_of_memory);
        let mut failure = out_of_memory.then_some(FsError::OutOfMemory);
        for run in &runs {
            let result = write_all(ops, run.offset, &run.buf).await;
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
            results.push(result);
        }
        settle_runs(&mut batch.pages, &runs, &results);
        drop(runs);
        let generation = ops.mmap_cache_generation();
        wrote += batch.finish(generation);
        drop(guard);
        if let Some(error) = failure {
            return Err(error);
        }
        match next {
            Some(offset) => from = offset,
            None => {
                return Ok(Progress {
                    wrote,
                    resume: None,
                })
            }
        }
        scheduling_point(caller).await;
    }
}

/// Who is running the engine, which decides how it gives up the CPU.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Caller {
    /// A syscall (`fsync`, `msync`, `sync`, `sendfile` flushing its source),
    /// on the calling task's own kernel stack.
    Syscall,
    /// A task the executor polls: the flusher.
    Task,
}

/// Linux `cond_resched()` between two writeback batches.
///
/// A syscall is not polled by the executor, so returning `Pending` from
/// here would only make its driver poll again. It yields the CPU outright
/// instead ([`crate::handlers::cond_resched`]) and continues once the
/// tasks queued behind it have run. A task returns to the executor, which
/// requeues it behind its peers.
/// In-syscall scheduling points where the caller really was a task on its
/// own stack (`cond_resched` could yield). Kernel tests read it.
pub(super) static SYSCALL_YIELD_POINTS: AtomicU64 = AtomicU64::new(0);

async fn scheduling_point(caller: Caller) {
    match caller {
        Caller::Syscall => {
            if crate::handlers::cond_resched() {
                SYSCALL_YIELD_POINTS.fetch_add(1, Ordering::Relaxed);
            }
        }
        Caller::Task => narf_scheduler::yield_now().await,
    }
}

/// The file's entry and the open to write it through.
fn lookup(identity: SharedFileIdentity) -> Option<(Arc<CachedFile>, Arc<dyn FileOps>)> {
    let pages = SHARED_FILE_PAGES.lock();
    pages.files.get(&identity).map(writer_of)
}

fn writer_of(slot: &FileSlot) -> (Arc<CachedFile>, Arc<dyn FileOps>) {
    (
        Arc::clone(&slot.file),
        Arc::clone(slot.writer.as_ref().unwrap_or(&slot.ops)),
    )
}

/// A mapping whose descriptor is open for writing reached this file's
/// cache: write the file through that open from now on. The open that
/// first brought a file into the cache may be read-only, and on a
/// filesystem whose opens carry their access mode a read-only open cannot
/// commit a page.
pub(super) fn note_writer(ops: &Arc<dyn FileOps>) {
    let identity = shared_file_identity(ops.as_ref());
    let previous = {
        let mut pages = SHARED_FILE_PAGES.lock();
        let Some(slot) = pages.files.get_mut(&identity) else {
            return;
        };
        if slot
            .writer
            .as_ref()
            .is_some_and(|writer| Arc::ptr_eq(writer, ops))
        {
            return;
        }
        slot.writer.replace(Arc::clone(ops))
    };
    // Outside the cache lock: this may be the last reference to that open.
    drop(previous);
}

/// The `write(2)` family's write of `bytes` to `ops` at `offset`, with the
/// cache told of it — one operation, under the file's writeback lock when
/// the file has a cache entry (Linux: `inode_lock` across
/// `generic_perform_write`, and the folio lock writeback also takes).
///
/// No writeback batch of the file can run between the filesystem write and
/// the cache update, so a batch can neither put older bytes on the file
/// after this write nor be mistaken about which reached it last. A file
/// with no entry — nearly every write — takes no lock: the filter turns it
/// away. Owned, so a killed writer's operation finishes — lock, write,
/// report — in the task it is handed to.
///
/// Lock order: the file's writeback lock is outermost. It is taken here
/// before the filesystem's own locks and the cache lock; a writeback batch
/// takes it before the cache lock and the filesystem's locks too. Callers
/// hold none of those.
pub(crate) async fn write_and_note(
    ops: Arc<dyn FileOps>,
    offset: u64,
    bytes: Vec<u8>,
) -> (Result<usize, FsError>, Vec<u8>) {
    let entry = entry_identity(ops.as_ref())
        .and_then(lookup)
        .map(|(file, _)| file);
    let guard = match entry.as_ref() {
        Some(file) => Some(file.lock.lock().await),
        None => None,
    };
    // A write that starts past EOF extends the file over bytes a mapping
    // may have stored past the old EOF: those must read as zeros
    // (`pagecache_isize_extended`). Only a file with cached pages can have
    // such bytes.
    if guard.is_some() && !ops.is_stream() {
        let size = ops.stat().size;
        if offset > size {
            discard_stores_past_eof(ops.as_ref(), size, offset);
        }
    }
    let stamp = if guard.is_some() {
        WriteStamp::locked()
    } else {
        write_stamp()
    };
    let result = ops.write(offset, &bytes).await;
    if let Ok(written) = result {
        if written != 0 && written <= bytes.len() {
            super::note_file_written(&ops, offset, &bytes[..written], stamp);
        }
    }
    drop(guard);
    (result, bytes)
}

/// `mmap(MAP_SHARED)` of a file through a descriptor open for writing:
/// from here on the file can be dirtied through a mapping. Record the open
/// for any page the mapping already took, start the task that will write
/// its pages back, and — `balance_dirty_pages` — hold the caller back if
/// dirtiers are already ahead of that task.
///
/// `pages` are the cache pages the mapping was populated with at `mmap`
/// time, if any (a lazy mapping takes its pages one fault at a time, and
/// the fault marks them): stores can reach them without another fault.
pub(crate) fn writable_mapping(ops: &Arc<dyn FileOps>, pages: &[PhysAddr]) {
    register_shrinker();
    if pages.iter().any(|phys| phys.raw() != 0) {
        let mut cache = SHARED_FILE_PAGES.lock();
        for phys in pages {
            if let Some(page) = cache.by_phys.get_mut(&phys.raw()) {
                page.maybe_dirty = true;
            }
        }
    }
    note_writer(ops);
    ensure_flusher();
    throttle_dirtier();
}

/// Drive a writeback future from a syscall. With a current task this parks
/// it on the filesystem's wakers; the future is never abandoned.
fn drive<F: Future>(future: F) -> Option<F::Output> {
    crate::handlers::poll_io_to_completion(future)
}

/// `fsync`/`fdatasync`/`msync(MS_SYNC)`: write the dirty cached pages of
/// `ops`'s file in `[from, end)` before the filesystem's own sync runs.
///
/// Reports this call's own failure, else a background failure nobody has
/// been told about yet — once.
pub(super) fn sync_file(ops: &Arc<dyn FileOps>, from: u64, end: u64) -> Result<(), FsError> {
    if FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return Ok(());
    }
    let Some(identity) = entry_identity(ops.as_ref()) else {
        return Ok(());
    };
    let Some((file, writer)) = lookup(identity) else {
        return Ok(());
    };
    let mut budget = usize::MAX;
    let from = from & !4095;
    let outcome = drive(write_range(
        &file,
        &writer,
        (from, end),
        Plan::SYNC,
        &mut budget,
    ));
    let result = match outcome {
        Some(Ok(progress)) => {
            // A write that reached the file ends any run of failures, and
            // the back-off with it.
            if progress.wrote != 0 {
                file.failed_passes.store(0, Ordering::Relaxed);
                file.skip_passes.store(0, Ordering::Relaxed);
            }
            match file.take_error() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
        Some(Err(error)) => Err(error),
        None => Err(FsError::Io(narf_block::BlockError::IOError)),
    };
    drop(file);
    drop(writer);
    // If that was the file's last unwritten page, the cache is done with it.
    release_if_unused(identity);
    result
}

/// A fault or an `mmap` is about to look up `count` cached pages of `ops`'s
/// file from `offset`. If one of them is unmapped, still waiting for
/// writeback, and was last vouched for under an older generation of the
/// file (or under none), run writeback over the range first.
///
/// Such a page is one of two things: holding a store that never reached
/// the file — then it stays dirty and is adopted, its data winning over the
/// file's as a dirty folio does on Linux — or simply not looked at yet, and
/// stale now that the file has changed behind it — then it is marked clean
/// here, and the generation rule for clean pages hands the new mapping a
/// fresh read instead. Without this the publication would adopt the page
/// either way, as it rightly does for a page whose generation is current.
pub(crate) fn settle_unverified(ops: &Arc<dyn FileOps>, offset: u64, count: usize) {
    if IDLE_DIRTY_PAGES.load(Ordering::Relaxed) == 0 {
        return;
    }
    let Some(identity) = entry_identity(ops.as_ref()) else {
        return;
    };
    let generation = ops.mmap_cache_generation();
    let first = offset & !4095;
    let end = first.saturating_add(count as u64 * 4096);
    // This runs on a page fault and in `mmap`: it compares, it never
    // writes. A filesystem write from here would run the whole write path
    // — on btrfs a copy-on-write extent update — on top of whatever the
    // faulting task's stack already holds. Pin the stale pages, compare
    // each with its clean image with no lock held, and settle the ones
    // that turn out clean; a page that really holds a store stays dirty
    // and is adopted, as before.
    let mut pinned: Vec<(u64, Arc<Vec<u8>>)> = Vec::new();
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        let SharedFilePages {
            by_phys,
            by_file,
            idle_dirty,
            ..
        } = &mut *pages;
        for listed in idle_dirty.range(key(identity, first)..) {
            if listed.file != identity || listed.offset >= end {
                break;
            }
            let Some(page) = by_file.get(listed).and_then(|phys| by_phys.get_mut(phys)) else {
                continue;
            };
            let stale = page.cache_generation.is_none() || page.cache_generation != generation;
            if !stale || page.wb_pins != 0 || pinned.try_reserve(1).is_err() {
                continue;
            }
            page.wb_pins += 1;
            page.redirtied = false;
            pinned.push((page.phys.raw(), Arc::clone(&page.clean)));
        }
    }
    if pinned.is_empty() {
        return;
    }
    let clean: Vec<bool> = pinned
        .iter()
        .map(|(phys, image)| {
            PAGE_COMPARES.fetch_add(1, Ordering::Relaxed);
            // SAFETY: pinned until the release below; identity-mapped.
            let live = unsafe {
                core::slice::from_raw_parts(PhysAddr::new(*phys).kernel_ptr::<u8>(), 4096)
            };
            live == image.as_slice()
        })
        .collect();
    let mut free: Vec<PhysAddr> = Vec::with_capacity(pinned.len());
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        let oldest_in_flight = IN_FLIGHT.lock().keys().next().copied();
        for ((phys, _), clean) in pinned.iter().zip(&clean) {
            let (cached, release) = pages.unpin(*phys);
            free.extend(release);
            if !cached || !clean {
                continue;
            }
            let Some(page) = pages.by_phys.get_mut(phys) else {
                continue;
            };
            let idle = page.mappings == 0 && page.pending == 0;
            if idle && !page.redirtied && settle_allowed(oldest_in_flight, page.wb_seq) {
                page.maybe_dirty = false;
                pages.clear_idle_dirty(*phys);
            }
        }
    }
    drop(pinned);
    for frame in free {
        narf_memory::free_frame(narf_memory::PhysFrame::new(frame));
    }
}

/// The kernel is about to consume `ops`'s file through the filesystem's own
/// pages or extents — the source of a `sendfile`/`splice`, either side of a
/// `copy_file_range` — where there is no buffer to overlay. Commit the
/// file's dirty cached pages first, so the transfer sees what a mapping of
/// the file shows (on Linux both go through the same page cache). A linker
/// that writes its output through a shared mapping and exits is followed at
/// once by something that copies that output.
///
/// A failure is recorded on the file, for its next `fsync`, like any other
/// writeback failure; the read proceeds.
pub(crate) fn flush_file_for_read(ops: &Arc<dyn FileOps>) {
    if FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    let Some(identity) = entry_identity(ops.as_ref()) else {
        return;
    };
    let Some((file, writer)) = lookup(identity) else {
        return;
    };
    let mut budget = usize::MAX;
    if let Some(Err(error)) = drive(write_range(
        &file,
        &writer,
        (0, u64::MAX),
        Plan::SYNC,
        &mut budget,
    )) {
        file.record_error(error);
    }
}

/// Cache-lock takes by [`overlay_dirty`]. Kernel tests read it.
pub(super) static OVERLAY_LOCKS: AtomicU64 = AtomicU64::new(0);

/// Make the bytes a kernel read just fetched from `ops` at `offset` agree
/// with the file's cached pages: wherever a cached page differs from its
/// clean image, the page's byte is the file's current content and replaces
/// what the filesystem returned. `read(2)` and a private page fault then see
/// a `MAP_SHARED` store that has not been written back yet, as they do on
/// Linux, where they read the same folio the mapping stores to.
///
/// Only the differing bytes are taken, so a page that is clean — or stale
/// in ways the filesystem already knows better — changes nothing.
///
/// `epoch` is [`read_epoch`] sampled before the filesystem read. A batch
/// that completed after it may have written a page and made it clean
/// between the read and this call: the filesystem may have returned the
/// bytes from before that write, and the page no longer differs from its
/// clean image to say so. For such a page the whole range is taken from
/// the page, which is what the batch put on the file.
pub(crate) fn overlay_dirty(ops: &Arc<dyn FileOps>, offset: u64, buf: &mut [u8], epoch: ReadEpoch) {
    if buf.is_empty() || FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    let Some(identity) = entry_identity(ops.as_ref()) else {
        return;
    };
    let end = offset.saturating_add(buf.len() as u64);
    let mut cursor = offset & !4095;
    // A few pages per hold of the cache lock; each is at most one 4 KiB
    // compare and a copy of the bytes that differ.
    const PAGES_PER_HOLD: usize = 4;
    loop {
        OVERLAY_LOCKS.fetch_add(1, Ordering::Relaxed);
        let pages = SHARED_FILE_PAGES.lock();
        if !pages.files.contains_key(&identity) {
            return;
        }
        let mut visited = 0usize;
        let mut resume = None;
        for (cached, phys) in pages.by_file.range(key(identity, cursor)..) {
            if cached.file != identity || cached.offset >= end {
                break;
            }
            if visited == PAGES_PER_HOLD {
                resume = Some(cached.offset);
                break;
            }
            let Some(page) = pages.by_phys.get(phys) else {
                continue;
            };
            let written_since = page.wb_seq > epoch.0;
            // Recorded state first: a page no writable mapping has held,
            // that is not waiting for writeback, and that no batch wrote
            // during the read, equals what the read returned.
            if !page.maybe_dirty && !page.idle_dirty && !written_since {
                continue;
            }
            visited += 1;
            PAGE_COMPARES.fetch_add(1, Ordering::Relaxed);
            let low = offset.max(cached.offset);
            let high = end.min(cached.offset + 4096);
            let in_page = (low - cached.offset) as usize;
            let count = (high - low) as usize;
            // SAFETY: the cache entry owns the frame while the cache lock
            // is held, and every frame is identity-mapped.
            let live = unsafe {
                core::slice::from_raw_parts(page.phys.kernel_ptr::<u8>().add(in_page), count)
            };
            let clean = &page.clean[in_page..in_page + count];
            let out = &mut buf[(low - offset) as usize..(low - offset) as usize + count];
            if written_since {
                out.copy_from_slice(live);
                continue;
            }
            if live == clean {
                continue;
            }
            for ((out, live), clean) in out.iter_mut().zip(live).zip(clean) {
                if live != clean {
                    *out = *live;
                }
            }
        }
        drop(pages);
        match resume {
            Some(offset) => cursor = offset,
            None => return,
        }
    }
}

/// Free up to a batch of `identity`'s cached pages in `[from, end)` that
/// nothing maps, and zero the rest in place — both the live page and its
/// clean image, so the page is clean and reads as the hole it now is.
/// Returns where to continue.
fn invalidate_step(identity: SharedFileIdentity, from: u64, end: u64) -> Option<u64> {
    let mut free: Vec<PhysAddr> = Vec::with_capacity(BATCH_PAGES);
    // On the heap: a 2 KiB array here sat in the frame of every truncate
    // and size change, on top of the filesystem's own stack use.
    let mut targets: Vec<u64> = Vec::with_capacity(BATCH_PAGES);
    let mut count = 0usize;
    let mut resume = None;
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        for (cached, phys) in pages.by_file.range(key(identity, from)..) {
            if cached.file != identity || cached.offset >= end {
                break;
            }
            if count == BATCH_PAGES {
                resume = Some(cached.offset);
                break;
            }
            targets.push(*phys);
            count += 1;
        }
        for phys in &targets[..count] {
            let unmapped = pages
                .by_phys
                .get(phys)
                .is_some_and(|page| page.mappings == 0 && page.pending == 0);
            if unmapped {
                if let Some(frame) = pages.retire_phys(*phys) {
                    free.push(frame);
                }
            } else if let Some(page) = pages.by_phys.get_mut(phys) {
                zero_cached(page, 0, 4096);
            }
        }
    }
    for frame in free {
        narf_memory::free_frame(narf_memory::PhysFrame::new(frame));
    }
    resume
}

/// Zero `[at, at + len)` of a cached page and of its clean image. Called
/// with the cache lock held.
fn zero_cached(page: &mut SharedFilePage, at: usize, len: usize) {
    // SAFETY: the cache entry owns the frame while the cache lock is held;
    // `at + len <= 4096` at every call site.
    unsafe {
        core::ptr::write_bytes(page.phys.kernel_mut_ptr::<u8>().add(at), 0, len);
    }
    Arc::make_mut(&mut page.clean)[at..at + len].fill(0);
    // A batch that holds this page has an image from before the change.
    page.redirtied = true;
}

/// Everything cached past `size` is gone from the file: drop it, and zero
/// the tail of the page `size` falls in (`truncate_inode_pages_range` and
/// `truncate_inode_partial_folio`).
fn invalidate_past(identity: SharedFileIdentity, size: u64) {
    if !may_have_entry(identity) {
        return;
    }
    let in_page = (size % 4096) as usize;
    if in_page != 0 {
        let mut pages = SHARED_FILE_PAGES.lock();
        let straddling = pages
            .by_file
            .get(&key(identity, size - in_page as u64))
            .copied();
        if let Some(page) = straddling.and_then(|phys| pages.by_phys.get_mut(&phys)) {
            zero_cached(page, in_page, 4096 - in_page);
        }
    }
    let Some(mut cursor) = size.checked_add(4095).map(|rounded| rounded & !4095) else {
        return;
    };
    while let Some(next) = invalidate_step(identity, cursor, u64::MAX) {
        cursor = next;
    }
}

/// The truncate bridge's cache half: `file` has (or is about to have) the
/// size it reports now.
pub(super) fn invalidate_beyond_eof(file: &dyn FileOps) {
    if FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    let Some(identity) = entry_identity(file) else {
        return;
    };
    invalidate_past(identity, file.stat().size);
}

/// `ops`'s file is about to grow from `old_size` to cover `new_end`, by a
/// `write(2)` past EOF, an `ftruncate` up, or `fallocate`. Bytes a mapping
/// stored past the old EOF in its last page are not file data and must
/// not become file data: the file reads zeros there. Restore them to the
/// page's clean image (zeros past EOF) — Linux `pagecache_isize_extended`,
/// and the zeroing `truncate_setsize` does on the old last page.
///
/// Only bytes that differ from the clean image are touched: a `write(2)`
/// that put bytes there updated both, so a racing writer's data is never
/// taken for a stray store. One page, under the cache lock.
pub(crate) fn discard_stores_past_eof(ops: &dyn FileOps, old_size: u64, new_end: u64) {
    let in_page = (old_size % 4096) as usize;
    if in_page == 0 || new_end <= old_size || FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    let Some(identity) = entry_identity(ops) else {
        return;
    };
    let end = (new_end - (old_size - in_page as u64)).min(4096) as usize;
    let mut pages = SHARED_FILE_PAGES.lock();
    let Some(phys) = pages
        .by_file
        .get(&key(identity, old_size - in_page as u64))
        .copied()
    else {
        return;
    };
    let Some(page) = pages.by_phys.get_mut(&phys) else {
        return;
    };
    // SAFETY: the cache entry owns the frame while the cache lock is held,
    // and `in_page < end <= 4096`.
    let live = unsafe {
        core::slice::from_raw_parts_mut(
            page.phys.kernel_mut_ptr::<u8>().add(in_page),
            end - in_page,
        )
    };
    for (byte, clean) in live.iter_mut().zip(&page.clean[in_page..end]) {
        if *byte != *clean {
            *byte = *clean;
        }
    }
    if page.wb_pins != 0 {
        page.redirtied = true;
    }
}

/// `fallocate(PUNCH_HOLE | ZERO_RANGE)` made `[offset, offset + len)` read
/// as zeros: so must the cached pages, or a dirty one would write the old
/// bytes back into the hole.
fn zero_cached_range(identity: SharedFileIdentity, offset: u64, len: u64) {
    let end = offset.saturating_add(len);
    let mut cursor = offset & !4095;
    loop {
        let mut resume = None;
        {
            let mut pages = SHARED_FILE_PAGES.lock();
            let SharedFilePages {
                by_phys, by_file, ..
            } = &mut *pages;
            for (visited, (cached, phys)) in by_file.range(key(identity, cursor)..).enumerate() {
                if cached.file != identity || cached.offset >= end {
                    break;
                }
                if visited == BATCH_PAGES {
                    resume = Some(cached.offset);
                    break;
                }
                let Some(page) = by_phys.get_mut(phys) else {
                    continue;
                };
                let low = offset.max(cached.offset);
                let high = end.min(cached.offset + 4096);
                zero_cached(page, (low - cached.offset) as usize, (high - low) as usize);
            }
        }
        match resume {
            Some(offset) => cursor = offset,
            None => return,
        }
    }
}

/// The file's entry, created if it has none, for a caller that needs its
/// lock. `release` undoes it.
fn acquire(ops: &Arc<dyn FileOps>) -> (Arc<CachedFile>, Arc<dyn FileOps>) {
    let identity = shared_file_identity(ops.as_ref());
    let mut pages = SHARED_FILE_PAGES.lock();
    let slot = pages
        .ensure_slot(identity, || Some(Arc::clone(ops)))
        .expect("an entry was just ensured");
    writer_of(slot)
}

/// Drop `identity`'s entry if nothing needs it: no mapped page, no
/// unwritten page, nobody else holding it, and no error still to report to
/// an open that could ask.
fn release_if_unused(identity: SharedFileIdentity) {
    let unused = {
        let mut pages = SHARED_FILE_PAGES.lock();
        let collect = pages.files.get(&identity).is_some_and(slot_is_unused);
        if collect {
            pages.remove_slot(identity)
        } else {
            None
        }
    };
    // Outside the cache lock: this may close the file.
    drop(unused);
    super::release_deferred_slots();
}

pub(super) fn slot_is_unused(slot: &FileSlot) -> bool {
    slot.held == 0
        && slot.idle_dirty == 0
        && Arc::strong_count(&slot.file) == 1
        && (!slot.file.has_error() || Arc::strong_count(&slot.ops) == 1)
}

/// Run a size-changing filesystem operation on `ops`'s file — `ftruncate`,
/// `truncate`, `O_TRUNC` — excluded from writeback, then drop what the new
/// size cut off.
///
/// Linux takes `mapping->invalidate_lock` and waits for writeback in
/// `truncate_inode_pages_range` to the same end. Without it, a batch that
/// copied a page before the truncate could write it afterwards: the data
/// would be back, and the file as long as before.
pub(crate) fn size_change_serialized<R>(ops: &Arc<dyn FileOps>, change: impl FnOnce() -> R) -> R {
    // A file with no cache entry has no page for writeback to write and none
    // to drop: every `open(O_TRUNC)` of an unmapped file — every shell
    // redirection — takes no lock and allocates nothing here.
    if entry_identity(ops.as_ref()).is_none() {
        return change();
    }
    let (file, _) = acquire(ops);
    // `None` only where there is nothing to park on and the lock never
    // came free; the operation must still run.
    let guard = drive(file.lock.lock());
    let old_size = ops.stat().size;
    let result = change();
    // The size the file has NOW, not the one asked for: a `write(2)` does
    // not take this lock and may have extended the file since.
    let new_size = ops.stat().size;
    discard_stores_past_eof(ops.as_ref(), old_size, new_size);
    invalidate_past(file.identity, new_size);
    drop(guard);
    let identity = file.identity;
    drop(file);
    release_if_unused(identity);
    result
}

const FALLOC_FL_PUNCH_HOLE: u64 = 0x02;
const FALLOC_FL_COLLAPSE_RANGE: u64 = 0x08;
const FALLOC_FL_ZERO_RANGE: u64 = 0x10;
const FALLOC_FL_INSERT_RANGE: u64 = 0x20;

/// Run `fallocate(mode, offset, len)` on `ops`'s file, excluded from
/// writeback, and bring the cache into line with what it did.
///
/// * `PUNCH_HOLE` / `ZERO_RANGE`: the range reads as zeros afterwards, in
///   the cache too.
/// * `COLLAPSE_RANGE` / `INSERT_RANGE` move the file's contents under the
///   cached pages. Linux writes the range out first
///   (`filemap_write_and_wait_range`) and truncates the page cache from
///   `offset`; the dirty pages are committed here before the operation for
///   the same reason, and the unmapped ones dropped after it.
/// * Every mode may change the size: what lies past the new EOF goes.
///
/// `succeeded` tells whether `change`'s result means the operation ran.
pub(crate) fn fallocate_serialized<R>(
    ops: &Arc<dyn FileOps>,
    mode: u64,
    offset: u64,
    len: u64,
    change: impl FnOnce() -> R,
    succeeded: impl FnOnce(&R) -> bool,
) -> R {
    if entry_identity(ops.as_ref()).is_none() {
        return change();
    }
    let (file, writer) = acquire(ops);
    let guard = drive(file.lock.lock());
    let shifts = mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE) != 0;
    if shifts {
        let mut budget = usize::MAX;
        if let Some(Err(error)) = drive(write_range(
            &file,
            &writer,
            (0, u64::MAX),
            Plan {
                select: Select::All,
                locked: true,
                caller: Caller::Syscall,
            },
            &mut budget,
        )) {
            file.record_error(error);
        }
    }
    let old_size = ops.stat().size;
    let result = change();
    discard_stores_past_eof(ops.as_ref(), old_size, ops.stat().size);
    if succeeded(&result) {
        if mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE) != 0 {
            zero_cached_range(file.identity, offset, len);
        }
        if shifts {
            // Linux `unmap_mapping_range` then `truncate_pagecache_range`
            // from the offset: every page from there on now holds other
            // file content. Take them out of every mapping first, so none
            // is still mapped — and zeroed in place — when it is dropped.
            let first = offset & !4095;
            if super::truncate_file_mappings(ops.as_ref(), first).is_err() {
                file.record_error(FsError::OutOfMemory);
            }
            let mut cursor = first;
            while let Some(next) = invalidate_step(file.identity, cursor, u64::MAX) {
                cursor = next;
            }
        }
    }
    invalidate_past(file.identity, ops.stat().size);
    drop(guard);
    let identity = file.identity;
    drop(file);
    drop(writer);
    release_if_unused(identity);
    result
}

/// Every file with an entry on `device` (`None`: on any device).
fn files_on(device: Option<u64>) -> Vec<(Arc<CachedFile>, Arc<dyn FileOps>)> {
    let pages = SHARED_FILE_PAGES.lock();
    pages
        .files
        .iter()
        .filter(|(identity, _)| device.is_none_or(|device| identity.device == device))
        .map(|(_, slot)| writer_of(slot))
        .collect()
}

/// `sync(2)`, `syncfs(2)`, an unmount, a shutdown: commit every dirty
/// cached page — of the files on `device`, or of all files — whoever
/// dirtied it and whether or not anything still has the file open. The
/// filesystem's own sync follows in the caller.
///
/// `sync` has no per-file error channel: a failure is recorded on its file
/// and the others are still written.
///
/// Returns the first error: this call's own write failure, else one
/// recorded earlier by background writeback on a file it covered (Linux
/// `syncfs` reports `sb->s_wb_err`). The recorded error is not consumed —
/// each file's next `fsync` still reports it.
pub(crate) fn sync_all_files(device: Option<u64>) -> Result<(), FsError> {
    super::release_deferred_slots();
    if FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return Ok(());
    }
    let mut first = None;
    for (file, writer) in files_on(device) {
        let mut budget = usize::MAX;
        match drive(write_range(
            &file,
            &writer,
            (0, u64::MAX),
            Plan::SYNC,
            &mut budget,
        )) {
            Some(Err(error)) => {
                file.record_error(error);
                first.get_or_insert(error);
            }
            None => {
                first.get_or_insert(FsError::Io(narf_block::BlockError::IOError));
            }
            Some(Ok(_)) => {
                if let Some(error) = *file.error.lock() {
                    first.get_or_insert(error);
                }
            }
        }
    }
    collect_unused();
    first.map_or(Ok(()), Err)
}

/// [`sync_all_files`] for a caller that is a task, not a syscall: the
/// orderly and emergency power-off paths, which do not go through
/// `reboot(2)` and so not through the pre-shutdown sync. Same engine, same
/// batches, awaited instead of driven.
pub(crate) async fn sync_all_files_async() {
    super::release_deferred_slots();
    if FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    for (file, writer) in files_on(None) {
        let mut budget = usize::MAX;
        if let Err(error) = write_range(
            &file,
            &writer,
            (0, u64::MAX),
            Plan::background(Select::All),
            &mut budget,
        )
        .await
        {
            file.record_error(error);
        }
    }
}

/// Whether a file of the filesystem `device` still has a page mapped. A
/// mapping holds its file's mount on Linux (`vma->vm_file` pins the
/// vfsmount), so a plain `umount` of it is `EBUSY`.
pub(crate) fn device_mapped(device: u64) -> bool {
    let pages = SHARED_FILE_PAGES.lock();
    pages
        .files
        .iter()
        .any(|(identity, slot)| identity.device == device && slot.held != 0)
}

/// The filesystem `device` has been unmounted, after [`sync_all_files`]
/// wrote what it could: let go of everything the cache holds for it, so no
/// entry keeps a file of the unmounted volume open and no later writeback
/// reaches it. Pages that could not be written are lost, with the count
/// logged — as Linux evicts the inodes of an unmounted filesystem after
/// `sync_filesystem` whatever that returned.
///
/// Device 0 names no filesystem in particular (one that does not track
/// devices); nothing is forgotten for it.
pub(crate) fn forget_device(device: u64) {
    if device == 0 {
        return;
    }
    let first = SharedFileIdentity { device, anchor: 0 };
    let mut lost = 0usize;
    loop {
        let mut free: Vec<PhysAddr> = Vec::new();
        let more = {
            let mut pages = SHARED_FILE_PAGES.lock();
            let victims: Vec<(u64, bool)> = pages
                .by_file
                .range(key(first, 0)..)
                .take_while(|(cached, _)| cached.file.device == device)
                .filter_map(|(_, phys)| pages.by_phys.get(phys))
                .filter(|page| page.mappings == 0 && page.pending == 0)
                .take(BATCH_PAGES)
                .map(|page| (page.phys.raw(), page.idle_dirty))
                .collect();
            for (phys, dirty) in &victims {
                lost += usize::from(*dirty);
                if let Some(frame) = pages.retire_phys(*phys) {
                    free.push(frame);
                }
            }
            victims.len() == BATCH_PAGES
        };
        for frame in free {
            narf_memory::free_frame(narf_memory::PhysFrame::new(frame));
        }
        if !more {
            break;
        }
    }
    let gone: Vec<FileSlot> = {
        let mut pages = SHARED_FILE_PAGES.lock();
        let identities: Vec<SharedFileIdentity> = pages
            .files
            .iter()
            .filter(|(identity, slot)| identity.device == device && slot.held == 0)
            .map(|(identity, _)| *identity)
            .collect();
        identities
            .into_iter()
            .filter_map(|identity| pages.remove_slot(identity))
            .collect()
    };
    drop(gone);
    if lost != 0 {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "writeback: dev {device:#x} unmounted with {lost} page(s) that could not be written"
        );
    }
}

/// Drop every entry nothing needs any more.
fn collect_unused() {
    let unused: Vec<FileSlot> = {
        let mut pages = SHARED_FILE_PAGES.lock();
        let identities: Vec<SharedFileIdentity> = pages
            .files
            .iter()
            .filter(|(_, slot)| slot_is_unused(slot))
            .map(|(identity, _)| *identity)
            .collect();
        identities
            .into_iter()
            .filter_map(|identity| pages.remove_slot(identity))
            .collect()
    };
    drop(unused);
}

/// Give up on `identity`'s unmapped dirty pages. Returns how many were
/// dropped.
#[cfg(feature = "kernel-test")]
fn drop_idle_dirty(identity: SharedFileIdentity) -> usize {
    let mut dropped = 0usize;
    loop {
        let mut free: Vec<PhysAddr> = Vec::with_capacity(BATCH_PAGES);
        let more = {
            let mut pages = SHARED_FILE_PAGES.lock();
            let listed: Vec<SharedFileKey> = pages
                .idle_dirty
                .range(key(identity, 0)..)
                .take_while(|listed| listed.file == identity)
                .take(BATCH_PAGES)
                .copied()
                .collect();
            for listed in &listed {
                let Some(phys) = pages.by_file.get(listed).copied() else {
                    if pages.idle_dirty.remove(listed) {
                        IDLE_DIRTY_PAGES.fetch_sub(1, Ordering::Relaxed);
                    }
                    continue;
                };
                dropped += 1;
                if let Some(frame) = pages.retire_phys(phys) {
                    free.push(frame);
                }
            }
            listed.len() == BATCH_PAGES
        };
        for frame in free {
            narf_memory::free_frame(narf_memory::PhysFrame::new(frame));
        }
        if !more {
            return dropped;
        }
    }
}

/// Account for one file's share of a background pass.
///
/// No page is ever dropped for failing to be written. A hard error has
/// already settled its pages (see [`transient`]); a transient one leaves
/// them dirty, and the file is skipped for a growing number of passes —
/// 1, 2, 4 … up to 12, a minute — so a full volume is not hammered every
/// five seconds. Both are logged once per file per run of failures, and
/// recorded for the next `fsync`.
fn pass_outcome(
    file: &Arc<CachedFile>,
    ops: &Arc<dyn FileOps>,
    outcome: &Result<Progress, FsError>,
) {
    let error = match outcome {
        Ok(progress) => {
            if progress.wrote != 0 {
                file.failed_passes.store(0, Ordering::Relaxed);
                file.skip_passes.store(0, Ordering::Relaxed);
            }
            return;
        }
        Err(error) => *error,
    };
    file.record_error(error);
    WRITE_ERRORS.fetch_add(1, Ordering::Relaxed);
    let failed = file.failed_passes.fetch_add(1, Ordering::Relaxed) + 1;
    if transient(error) {
        let skip = 1u32.checked_shl(failed.min(4) - 1).unwrap_or(12).min(12);
        file.skip_passes.store(skip, Ordering::Relaxed);
    }
    if failed == 1 {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "writeback: dev {:#x} ino {}: write failed, errno {}{}",
            file.identity.device,
            ops.ino(),
            crate::handlers::copy_fs_errno(error),
            if transient(error) {
                "; pages kept dirty, retrying"
            } else {
                "; reported to the next fsync, pages no longer dirty"
            },
        );
    }
}

/// Whether the background pass should leave `file` alone this time.
fn backing_off(file: &CachedFile) -> bool {
    file.skip_passes
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |skip| {
            skip.checked_sub(1)
        })
        .is_ok()
}

/// Where the sweep over mapped pages resumes.
static SWEEP_CURSOR: IrqSafeSpinLock<Option<SharedFileKey>> = IrqSafeSpinLock::new(None);

/// The first file with a cached page at or after `cursor` that has an
/// entry, and the offset to start at.
fn next_swept(
    mut cursor: Option<SharedFileKey>,
) -> Option<(Arc<CachedFile>, Arc<dyn FileOps>, u64)> {
    let pages = SHARED_FILE_PAGES.lock();
    loop {
        let found = match cursor {
            Some(cursor) => pages.by_file.range(cursor..).next(),
            None => pages.by_file.iter().next(),
        }
        .map(|(cached, _)| *cached)?;
        if let Some(slot) = pages.files.get(&found.file) {
            let (file, ops) = writer_of(slot);
            return Some((file, ops, found.offset));
        }
        // Retained clean pages of a file with no entry: step over the file.
        cursor = Some(key(found.file, u64::MAX));
    }
}

static PASSES: AtomicU64 = AtomicU64::new(0);
static PAGES_WRITTEN: AtomicU64 = AtomicU64::new(0);
static WRITE_ERRORS: AtomicU64 = AtomicU64::new(0);

/// One pass of the flusher (`wb_writeback`).
async fn background_pass() {
    PASSES.fetch_add(1, Ordering::Relaxed);
    super::release_deferred_slots();

    // Pages nobody maps: all of them. They cannot change any more, and they
    // are memory the cache cannot release until they are on the file.
    let idle: Vec<(Arc<CachedFile>, Arc<dyn FileOps>)> = {
        let pages = SHARED_FILE_PAGES.lock();
        pages
            .files
            .values()
            .filter(|slot| slot.idle_dirty != 0)
            .map(writer_of)
            .collect()
    };
    for (file, ops) in idle {
        if backing_off(&file) {
            continue;
        }
        let mut budget = usize::MAX;
        let outcome = write_range(
            &file,
            &ops,
            (0, u64::MAX),
            Plan::background(Select::Idle),
            &mut budget,
        )
        .await;
        if let Ok(progress) = &outcome {
            PAGES_WRITTEN.fetch_add(progress.wrote as u64, Ordering::Relaxed);
        }
        pass_outcome(&file, &ops, &outcome);
        narf_scheduler::yield_now().await;
    }

    // Mapped pages: a bounded stretch of the cache per pass, resumed next
    // time. Finding a dirty one is a compare per page, so the bound is what
    // keeps a large mapping from costing a full scan every five seconds.
    let mut budget = SWEEP_PAGES_PER_PASS;
    let mut cursor = SWEEP_CURSOR.lock().take();
    while budget != 0 {
        let Some((file, ops, from)) = next_swept(cursor) else {
            cursor = None;
            break;
        };
        // Backing off after a transient failure (counted down by the idle
        // half of the pass): step over the file this time.
        if file.skip_passes.load(Ordering::Relaxed) != 0 {
            cursor = Some(key(file.identity, u64::MAX));
            continue;
        }
        let outcome = write_range(
            &file,
            &ops,
            (from, u64::MAX),
            Plan::background(Select::Aged),
            &mut budget,
        )
        .await;
        if let Ok(progress) = &outcome {
            PAGES_WRITTEN.fetch_add(progress.wrote as u64, Ordering::Relaxed);
        }
        cursor = match &outcome {
            Ok(Progress {
                resume: Some(offset),
                ..
            }) => Some(key(file.identity, *offset)),
            _ => Some(key(file.identity, u64::MAX)),
        };
        pass_outcome(&file, &ops, &outcome);
        narf_scheduler::yield_now().await;
    }
    *SWEEP_CURSOR.lock() = cursor;

    collect_unused();
}

static KICKED: AtomicBool = AtomicBool::new(false);
static FLUSHER_WAKER: IrqSafeSpinLock<Option<Waker>> = IrqSafeSpinLock::new(None);
static FLUSHER_STARTED: AtomicBool = AtomicBool::new(false);

/// Ask the flusher for a pass now instead of at its next tick. Does no I/O
/// and takes no filesystem lock; callable from any syscall.
pub(super) fn kick() {
    if KICKED.swap(true, Ordering::AcqRel) {
        return;
    }
    let waker = FLUSHER_WAKER.lock().take();
    if let Some(waker) = waker {
        waker.wake();
    }
}

/// The flusher's sleep: until it is kicked or the writeback interval ends.
struct NextPass {
    tick: narf_time::SleepUntil,
}

impl Future for NextPass {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if KICKED.swap(false, Ordering::AcqRel) {
            return Poll::Ready(());
        }
        *FLUSHER_WAKER.lock() = Some(cx.waker().clone());
        // A kick between the test above and the registration found no
        // waker to wake.
        if KICKED.swap(false, Ordering::AcqRel) {
            return Poll::Ready(());
        }
        Pin::new(&mut this.tick).poll(cx)
    }
}

/// Whether anything can still make a cached page dirty: only a user task
/// can store through a mapping.
fn dirtiers_alive() -> bool {
    narf_scheduler::live_user_task_count() != 0
}

/// `u64::MAX`: use [`WRITEBACK_INTERVAL_MS`]. Tests shorten it.
static WRITEBACK_INTERVAL_OVERRIDE_MS: AtomicU64 = AtomicU64::new(u64::MAX);

fn writeback_interval_ms() -> u64 {
    match WRITEBACK_INTERVAL_OVERRIDE_MS.load(Ordering::Relaxed) {
        u64::MAX => WRITEBACK_INTERVAL_MS,
        ms => ms,
    }
}

/// Clears [`FLUSHER_STARTED`] however the flusher ends — returning, or its
/// task being dropped — so a later dirtier can start another.
struct FlusherRunning;

impl Drop for FlusherRunning {
    fn drop(&mut self) {
        FLUSHER_STARTED.store(false, Ordering::Release);
    }
}

/// `running` is created with the task, not in its first poll: a task that
/// is dropped before it ever runs must clear the flag too.
async fn flusher_main(running: FlusherRunning) {
    loop {
        background_pass().await;
        // Not merely "no user task": the last one may have exited between
        // that pass and this test, leaving the pages it unmapped on the way
        // out. They are written by the next pass, and only then does the
        // flusher go.
        if !dirtiers_alive() && IDLE_DIRTY_PAGES.load(Ordering::Acquire) == 0 {
            break;
        }
        NextPass {
            tick: narf_time::sleep_ms(writeback_interval_ms()),
        }
        .await;
    }
    drop(running);
    // A dirtier that appeared between the test above and the flag clearing
    // found the task still marked as running.
    if IDLE_DIRTY_PAGES.load(Ordering::Acquire) != 0 {
        start_flusher();
    } else {
        ensure_flusher();
    }
}

/// Start the writeback task if it is not running and there is anybody to
/// write back for.
///
/// It is an ordinary kernel task — it parks on the filesystem's wakers and
/// on its timer like any other, and a nested executor round can run it —
/// and it may run on any CPU, so one busy CPU cannot strand it. It lives as
/// long as a user task does: from the first writable shared file mapping
/// until the last process is gone, which on a running system is until
/// shutdown. (It ends rather than sleeping for ever so that an executor
/// drained to empty, as the in-kernel test harness drains it, is not kept
/// from emptying.)
pub(crate) fn ensure_flusher() {
    if !dirtiers_alive() {
        return;
    }
    start_flusher();
}

/// Flushers started. Kernel tests read it.
static FLUSHER_STARTS: AtomicU64 = AtomicU64::new(0);

fn start_flusher() {
    if FLUSHER_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    FLUSHER_STARTS.fetch_add(1, Ordering::Relaxed);
    let spec = narf_scheduler::TaskSpec {
        affinity: narf_scheduler::Affinity::any(),
        work_kind: narf_scheduler::WorkKind::KernelThread,
        ..narf_scheduler::TaskSpec::unthrottled()
    };
    narf_scheduler::spawn_with_spec(flusher_main(FlusherRunning), spec);
}

/// Pages of memory one cached page costs: its frame and its clean image.
const PAGES_PER_CACHED_PAGE: usize = 2;

/// The reclaimer's view of the cache: unmapped clean pages kept for reuse
/// (frame plus clean image each). Dirty pages are not reclaimable — they
/// are the only copy of their data — and the flusher is kicked instead.
fn shrink_count() -> usize {
    SHARED_FILE_PAGES
        .try_lock()
        .map_or(0, |pages| pages.idle_clean.len() * PAGES_PER_CACHED_PAGE)
}

/// Drop up to `nr_pages` pages' worth of unmapped clean pages, oldest
/// listed first. Linux reclaims clean page cache the same way
/// (`shrink_folio_list` on the inactive list). Never waits: a cache lock
/// already held — reclaim run under it — frees nothing this time.
fn shrink_scan(nr_pages: usize) -> usize {
    if IDLE_DIRTY_PAGES.load(Ordering::Relaxed) != 0 {
        kick();
    }
    let want = nr_pages / PAGES_PER_CACHED_PAGE;
    if want == 0 {
        return 0;
    }
    let mut freed = 0usize;
    // One frame at a time, outside the lock: no allocation on this path.
    while freed < want {
        let frame = {
            let Some(mut pages) = SHARED_FILE_PAGES.try_lock() else {
                break;
            };
            let Some(victim) = pages.idle_clean.iter().next().copied() else {
                break;
            };
            EVICTIONS.fetch_add(1, Ordering::Relaxed);
            pages.retire_phys(victim)
        };
        // The clean image went with the page: freed whether or not the
        // frame could be (a frame a batch still holds is freed by it).
        freed += 1;
        if let Some(frame) = frame {
            narf_memory::free_frame(narf_memory::PhysFrame::new(frame));
        }
    }
    freed * PAGES_PER_CACHED_PAGE
}

/// Register the cache with the reclaimer, once.
pub(crate) fn register_shrinker() {
    static REGISTERED: AtomicBool = AtomicBool::new(false);
    if REGISTERED.swap(true, Ordering::AcqRel) {
        return;
    }
    narf_memory::reclaim::register_shrinker(narf_memory::reclaim::Shrinker {
        name: "shared-file-pages",
        count: shrink_count,
        scan: shrink_scan,
    });
}

static DIRTY_LIMIT: AtomicUsize = AtomicUsize::new(0);

/// Unmapped dirty pages allowed before a dirtier is made to wait. Each one
/// costs two pages — its frame and its 4 KiB clean image on the kernel heap
/// — so the bound is a sixteenth of memory in pages, an eighth in bytes
/// (Linux `dirty_ratio` is a fifth of what it calls dirtyable).
fn dirty_limit() -> usize {
    match DIRTY_LIMIT.load(Ordering::Relaxed) {
        0 => {
            let limit = (narf_memory::frame::stats().total / 16).max(256);
            DIRTY_LIMIT.store(limit, Ordering::Relaxed);
            limit
        }
        limit => limit,
    }
}

const THROTTLE_SLEEP_MS: u64 = 20;

/// Longest one call waits (2 s). A flusher that cannot make progress — a
/// device that has stopped answering — must slow dirtiers down, not stop
/// them.
const THROTTLE_ROUNDS: usize = 100;

/// `balance_dirty_pages`: a task about to create more dirty file pages, or
/// that has just left some behind, waits here while the flusher is behind.
///
/// The wait is `TASK_KILLABLE` and bounded. It is entered only from
/// `mmap` and `munmap` — never from address-space teardown, which has no
/// task to make wait, and never from the writeback task, which is what the
/// wait is for.
pub(crate) fn throttle_dirtier() {
    let limit = dirty_limit();
    if IDLE_DIRTY_PAGES.load(Ordering::Relaxed) <= limit {
        return;
    }
    ensure_flusher();
    for _ in 0..THROTTLE_ROUNDS {
        if IDLE_DIRTY_PAGES.load(Ordering::Relaxed) <= limit {
            return;
        }
        kick();
        THROTTLE_WAITS.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "kernel-test")]
        tests::throttle_round();
        let nap: crate::killable_wait::OwnedWait<()> =
            Box::pin(async { narf_time::sleep_ms(THROTTLE_SLEEP_MS).await });
        match crate::killable_wait::wait(nap) {
            Ok(Some(())) => {}
            // Killed, or nothing to park on: stop waiting.
            Ok(None) | Err(crate::killable_wait::Killed) => return,
        }
    }
}

static THROTTLE_WAITS: AtomicU64 = AtomicU64::new(0);

/// Pages left behind by an unmap are the flusher's now: make sure it is
/// running and knows. For `munmap`, which has a task to do this from.
pub(crate) fn unmapped() {
    super::release_deferred_slots();
    if IDLE_DIRTY_PAGES.load(Ordering::Relaxed) == 0 {
        return;
    }
    ensure_flusher();
    kick();
}

/// The same for address-space teardown, which runs wherever the last
/// reference drops: make sure a flusher exists for what was left behind and
/// wake it. Spawning is a run-queue insertion — no I/O, no filesystem lock,
/// no wait.
pub(super) fn torn_down() {
    // After memory has let go of the space's frames, outside its locks.
    super::release_deferred_slots();
    if IDLE_DIRTY_PAGES.load(Ordering::Relaxed) != 0 {
        start_flusher();
        kick();
    }
}

#[cfg(feature = "kernel-test")]
#[path = "writeback_tests.rs"]
mod tests;
