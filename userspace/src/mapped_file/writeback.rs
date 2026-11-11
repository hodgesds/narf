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

fn filter_bucket(identity: SharedFileIdentity) -> &'static AtomicU32 {
    let mixed = (identity.anchor as u64 ^ identity.device.rotate_left(32))
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    &FILTER[(mixed >> 54) as usize % FILTER_BUCKETS]
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
    lock: narf_lib::mutex::Mutex<()>,
    /// A background write failure nobody has been told about. Reported once,
    /// by the next `fsync`/`msync` of the file (Linux `errseq_t` in
    /// `address_space::wb_err`, without its per-open cursor: here the first
    /// caller to ask is the one that sees it).
    error: IrqSafeSpinLock<Option<FsError>>,
    failed_passes: AtomicU32,
}

impl CachedFile {
    pub(super) fn new(identity: SharedFileIdentity) -> Arc<Self> {
        Arc::new(Self {
            identity,
            lock: narf_lib::mutex::Mutex::new(()),
            error: IrqSafeSpinLock::new(None),
            failed_passes: AtomicU32::new(0),
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

static WRITEBACK_SEQ: AtomicU64 = AtomicU64::new(0);

/// "No writeback batch has completed since" — taken by a `write(2)` before
/// it writes, and compared in [`super::note_file_written`] with the batch
/// number each cached page was last written by.
#[derive(Copy, Clone)]
pub(crate) struct WriteStamp(pub(super) u64);

pub(crate) fn write_stamp() -> WriteStamp {
    WriteStamp(WRITEBACK_SEQ.load(Ordering::Acquire))
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
    /// The write failed, or there was no memory to do it. The page stays
    /// dirty.
    Failed,
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
    identity: SharedFileIdentity,
    from: u64,
    end: u64,
    select: Select,
    scan: usize,
) -> (Vec<Pinned>, Option<u64>, usize) {
    let mut batch: Vec<Pinned> = Vec::new();
    if batch.try_reserve_exact(BATCH_PAGES).is_err() {
        return (batch, None, 0);
    }
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
fn examine(batch: &mut [Pinned], size: u64, select: Select) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
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
        let live = unsafe { core::slice::from_raw_parts(page.phys.kernel_ptr::<u8>(), 4096) };
        PAGE_COMPARES.fetch_add(1, Ordering::Relaxed);
        if live[..len] == page.clean[..len] {
            if page.idle && live[len..] != page.clean[len..] {
                page.action = Action::PastEof;
            }
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
            Ok(()) => {
                let mut image = Vec::new();
                if image.try_reserve_exact(4096).is_err() {
                    // Written, but with no memory to record it the page
                    // simply stays dirty and is written again.
                    Action::Failed
                } else {
                    image.extend_from_slice(&runs[run].buf[at..at + len]);
                    image.extend_from_slice(&page.clean[len..]);
                    Action::Written(Arc::new(image))
                }
            }
            Err(_) => Action::Failed,
        };
    }
}

/// Step 5 of a batch: record what was written and release the pins.
/// Returns the number of pages written.
fn finish_batch(batch: Vec<Pinned>, generation: Option<u64>) -> usize {
    let mut free: Vec<PhysAddr> = Vec::with_capacity(batch.len());
    // Old clean images, dropped after the cache lock.
    let mut garbage: Vec<Arc<Vec<u8>>> = Vec::with_capacity(batch.len() * 2);
    let mut wrote = 0usize;
    {
        let mut pages = SHARED_FILE_PAGES.lock();
        // Under the cache lock: a `write(2)` that sampled the counter before
        // this point sees these pages as written after it began.
        let seq = WRITEBACK_SEQ.fetch_add(1, Ordering::AcqRel) + 1;
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
}

impl Batch {
    /// Step 5: record what was written and unpin. Returns pages written.
    fn finish(mut self, generation: Option<u64>) -> usize {
        finish_batch(core::mem::take(&mut self.pages), generation)
    }
}

impl Drop for Batch {
    fn drop(&mut self) {
        if !self.pages.is_empty() {
            // Abandoned before its writes were accounted: nothing is marked
            // written, every queued page simply stays dirty.
            finish_batch(core::mem::take(&mut self.pages), None);
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
        let guard = if locked {
            None
        } else {
            Some(file.lock.lock().await)
        };
        let (pages, next, examined) = pin_batch(
            file.identity,
            from,
            end,
            select,
            (*budget).min(SCAN_PER_HOLD),
        );
        let mut batch = Batch { pages };
        *budget = budget.saturating_sub(examined.max(1));
        // Sampled under the file lock: no truncate can move it before the
        // writes below, so a batch never writes past the size it saw.
        let size = ops.stat().size;
        let runs = examine(&mut batch.pages, size, select);
        let mut results: Vec<Result<(), FsError>> = Vec::with_capacity(runs.len());
        let mut failure = None;
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
async fn scheduling_point(caller: Caller) {
    match caller {
        Caller::Syscall => {
            crate::handlers::cond_resched();
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
    let identity = shared_file_identity(ops.as_ref());
    if !may_have_entry(identity) {
        return Ok(());
    }
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
            if progress.wrote != 0 {
                file.failed_passes.store(0, Ordering::Relaxed);
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
/// Such a page is one of two things, and only writeback can tell which
/// without comparing its bytes here: holding a store that never reached
/// the file — then it must be written, so the fresh read that follows
/// includes it — or simply not looked at yet, and stale now that the file
/// has changed behind it — then it must not be handed to the new mapping.
/// Writeback settles both: it writes the first and marks the second clean,
/// after which the generation rules for clean pages apply as ever. Without
/// this the publication would adopt the page either way, as it rightly does
/// for a page whose generation is current.
pub(crate) fn settle_unverified(ops: &Arc<dyn FileOps>, offset: u64, count: usize) {
    if IDLE_DIRTY_PAGES.load(Ordering::Relaxed) == 0 {
        return;
    }
    let identity = shared_file_identity(ops.as_ref());
    if !may_have_entry(identity) {
        return;
    }
    let generation = ops.mmap_cache_generation();
    let first = offset & !4095;
    let end = first.saturating_add(count as u64 * 4096);
    let unsettled = {
        let pages = SHARED_FILE_PAGES.lock();
        pages
            .idle_dirty
            .range(key(identity, first)..)
            .take_while(|listed| listed.file == identity && listed.offset < end)
            .filter_map(|listed| pages.by_file.get(listed))
            .filter_map(|phys| pages.by_phys.get(phys))
            .any(|page| page.cache_generation.is_none() || page.cache_generation != generation)
    };
    if unsettled {
        // A failure leaves the page listed, and it is adopted as before.
        let _ = sync_file(ops, first, end);
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
    let identity = shared_file_identity(ops.as_ref());
    if !may_have_entry(identity) {
        return;
    }
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

/// Make the bytes a kernel read just fetched from `ops` at `offset` agree
/// with the file's cached pages: wherever a cached page differs from its
/// clean image, the page's byte is the file's current content and replaces
/// what the filesystem returned. `read(2)` and a private page fault then see
/// a `MAP_SHARED` store that has not been written back yet, as they do on
/// Linux, where they read the same folio the mapping stores to.
///
/// Only the differing bytes are taken, so a page that is clean — or stale
/// in ways the filesystem already knows better — changes nothing.
pub(crate) fn overlay_dirty(ops: &Arc<dyn FileOps>, offset: u64, buf: &mut [u8]) {
    if buf.is_empty() || FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    let identity = shared_file_identity(ops.as_ref());
    if !may_have_entry(identity) {
        return;
    }
    let end = offset.saturating_add(buf.len() as u64);
    let mut cursor = offset & !4095;
    // A few pages per hold of the cache lock; each is at most one 4 KiB
    // compare and a copy of the bytes that differ.
    const PAGES_PER_HOLD: usize = 4;
    loop {
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
            // Recorded state first: a page no writable mapping has held,
            // and that is not waiting for writeback, equals the file.
            if !page.maybe_dirty && !page.idle_dirty {
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
            if live == clean {
                continue;
            }
            let out = &mut buf[(low - offset) as usize..(low - offset) as usize + count];
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
    let mut targets: [u64; BATCH_PAGES] = [0; BATCH_PAGES];
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
            targets[count] = *phys;
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
    let identity = shared_file_identity(file);
    if !may_have_entry(identity) {
        return;
    }
    invalidate_past(identity, file.stat().size);
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
    let (file, _) = acquire(ops);
    // `None` only where there is nothing to park on and the lock never
    // came free; the operation must still run.
    let guard = drive(file.lock.lock());
    let result = change();
    // The size the file has NOW, not the one asked for: a `write(2)` does
    // not take this lock and may have extended the file since.
    invalidate_past(file.identity, ops.stat().size);
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
    let result = change();
    if succeeded(&result) {
        if mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE) != 0 {
            zero_cached_range(file.identity, offset, len);
        }
        if shifts {
            let mut cursor = offset & !4095;
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
pub(crate) fn sync_all_files(device: Option<u64>) {
    if FILE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    for (file, writer) in files_on(device) {
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
    collect_unused();
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
/// Only a write that reached the file ends a run of failed passes. A pass
/// visits a file twice — its unmapped pages, then its mapped ones — and the
/// second visit usually has nothing to write: counting that as success
/// would wipe out the failure the first visit had just recorded, and a file
/// whose writes never succeed would never be given up on.
fn pass_outcome(
    file: &Arc<CachedFile>,
    ops: &Arc<dyn FileOps>,
    outcome: &Result<Progress, FsError>,
) {
    let error = match outcome {
        Ok(progress) => {
            if progress.wrote != 0 {
                file.failed_passes.store(0, Ordering::Relaxed);
            }
            return;
        }
        Err(error) => *error,
    };
    file.record_error(error);
    WRITE_ERRORS.fetch_add(1, Ordering::Relaxed);
    let failed = file.failed_passes.fetch_add(1, Ordering::Relaxed) + 1;
    if failed < MAX_FAILED_PASSES {
        return;
    }
    file.failed_passes.store(0, Ordering::Relaxed);
    let dropped = drop_idle_dirty(file.identity);
    if dropped != 0 {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "writeback: dev {:#x} ino {}: {} dirty page(s) of a file nothing maps were dropped \
             after {} failed passes, errno {}",
            file.identity.device,
            ops.ino(),
            dropped,
            MAX_FAILED_PASSES,
            crate::handlers::copy_fs_errno(error),
        );
    }
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

async fn flusher_main() {
    loop {
        background_pass().await;
        if !dirtiers_alive() {
            break;
        }
        NextPass {
            tick: narf_time::sleep_ms(WRITEBACK_INTERVAL_MS),
        }
        .await;
    }
    FLUSHER_STARTED.store(false, Ordering::Release);
    // A dirtier that appeared between the test above and the store found
    // the task still marked as running.
    ensure_flusher();
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
    if FLUSHER_STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let spec = narf_scheduler::TaskSpec {
        affinity: narf_scheduler::Affinity::any(),
        work_kind: narf_scheduler::WorkKind::KernelThread,
        ..narf_scheduler::TaskSpec::unthrottled()
    };
    narf_scheduler::spawn_with_spec(flusher_main(), spec);
}

static DIRTY_LIMIT: AtomicUsize = AtomicUsize::new(0);

/// Unmapped dirty pages allowed before a dirtier is made to wait: an eighth
/// of memory (Linux `dirty_ratio` is a fifth of what it calls dirtyable).
fn dirty_limit() -> usize {
    match DIRTY_LIMIT.load(Ordering::Relaxed) {
        0 => {
            let limit = (narf_memory::frame::stats().total / 8).max(256);
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
    if IDLE_DIRTY_PAGES.load(Ordering::Relaxed) == 0 {
        return;
    }
    ensure_flusher();
    kick();
}

/// The same for address-space teardown, which runs on the executor thread:
/// wake the flusher if it is waiting, and nothing else. No task is started
/// from there; a page can only have been dirtied through a writable
/// mapping, and creating one started the flusher.
pub(super) fn torn_down() {
    if IDLE_DIRTY_PAGES.load(Ordering::Relaxed) != 0 {
        kick();
    }
}

#[cfg(feature = "kernel-test")]
#[path = "writeback_tests.rs"]
mod tests;
