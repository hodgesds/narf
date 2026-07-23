//! QSBR — quiescent-state-based reclamation.
//!
//! Spec: `rcu/specification/spec.md` §3.3 + §3.7. The idea is minimal:
//!
//! - A monotonic **global epoch** counter. `sync()` samples it, then
//!   waits for every CPU to have reported quiescence with a local
//!   "last-seen" epoch `>= target`.
//! - A **per-CPU reader-in-flight counter** (`active_readers`). `pin()`
//!   bumps it; the guard's `Drop` bumps it down. A CPU counts as
//!   quiescent for epoch `E` when it stores `E` into `last_quiescent`
//!   *and* `active_readers == 0` at that moment.
//! - A **per-CPU deferred-drop queue** stamped with the enqueue epoch.
//!   Draining happens either in `sync()` or (Stage-3 main track) from
//!   a per-domain reclamation-worker Future.
//!
//! Stage-2 scope (this crate):
//! - Single-CPU Stage-2 means `all_cpus_past` is cheap, but we still
//!   write it in the general SMP form so Stage-3 AP bring-up works
//!   without re-plumbing.
//! - `MAX_CPUS` from `narf_lib::percpu::MAX_CPUS` caps the arrays.
//! - Reclamation runs in-line on `sync()`; no worker Future yet.
//!
//! Invariants (spec §4): an object queued at epoch `E` is not dropped
//! until every CPU has `last_quiescent >= E`, observed with
//! `active_readers == 0`. On a well-behaved QSBR caller (§3.3) readers
//! do not span `.await`, so at any quiescent moment `active_readers` is
//! 0 for this CPU anyway.

use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll};

use narf_lib::percpu::MAX_CPUS;

// ── Global state ────────────────────────────────────────────────────

/// Monotonically-increasing global epoch. `sync()` does
/// `fetch_add(1, Release)` to publish a target and waits for every CPU
/// to cross it.
static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(1);

/// Per-CPU quiescence bookkeeping.
#[derive(Debug)]
struct CpuCell {
    /// Number of live `ReadGuard`s pinning this CPU's epoch. A CPU is
    /// quiescent only when this is 0.
    active_readers: AtomicUsize,
    /// Latest global epoch this CPU has reported quiescence for.
    last_quiescent: AtomicU64,
    /// Deferred-drop bucket — written only from this CPU.
    bucket: UnsafeCell<DeferBucket>,
}

impl CpuCell {
    // Initial `last_quiescent = u64::MAX` means "this CPU is not active,
    // and therefore vacuously past every epoch". Offline / unscheduled
    // CPUs otherwise pin `min_last_quiescent` to 0 forever and block all
    // reclamation. A CPU that comes online pulls this down to the
    // current epoch on its first `pin()` or `report_quiescent()` call.
    const NEW: Self = Self {
        active_readers: AtomicUsize::new(0),
        last_quiescent: AtomicU64::new(u64::MAX),
        bucket: UnsafeCell::new(DeferBucket::new()),
    };
}

// SAFETY: the `UnsafeCell<DeferBucket>` is only ever accessed via the
// current-CPU indexing helper with interrupts logically scoped to a
// single handler; cross-CPU access is forbidden by construction.
unsafe impl Sync for CpuCell {}

static CPUS: [CpuCell; MAX_CPUS] = [const { CpuCell::NEW }; MAX_CPUS];

#[inline]
fn this_cpu() -> &'static CpuCell {
    let idx = narf_arch::current_cpu_id().raw() as usize;
    // Stage-2 single-CPU: always 0. The clamp keeps Stage-3 safe if an
    // AP comes up with an ID out of our MAX_CPUS bound.
    &CPUS[if idx < MAX_CPUS { idx } else { 0 }]
}

// ── Deferred-drop per-CPU bucket ────────────────────────────────────
//
// Fixed-capacity ring: Stage-2 has no lock-free queue primitive in
// `lib/` we can borrow, and Stage-3 main track will install a real
// intrusive queue driven by the domain reclamation worker. Bucket
// overflow is surfaced via `overflow_count_this_cpu()`.

const DEFER_BUCKET_CAP: usize = 64;

#[derive(Copy, Clone)]
struct DeferEntry {
    ptr: *mut (),
    dropper: Option<unsafe fn(*mut ())>,
    epoch: u64,
}

// SAFETY: `DeferEntry` is a plain-old-data triple. The pointer's `T`
// was `Send + 'static` at enqueue (see `enqueue_drop`), so moving the
// entry across CPUs is sound.
unsafe impl Send for DeferEntry {}
// SAFETY: same reasoning as Send — the captured pointer and dropper
// don't expose interior state outside the single thread that owns the
// bucket.
unsafe impl Sync for DeferEntry {}

struct DeferBucket {
    len: usize,
    slots: [DeferEntry; DEFER_BUCKET_CAP],
    /// Drops silently discarded due to bucket overflow. Surfaced to the
    /// test harness + (eventually) `tracing/`.
    overflow: usize,
}

impl DeferBucket {
    const fn new() -> Self {
        Self {
            len: 0,
            slots: [DeferEntry {
                ptr: core::ptr::null_mut(),
                dropper: None,
                epoch: 0,
            }; DEFER_BUCKET_CAP],
            overflow: 0,
        }
    }
}

// ── Pin / unpin ─────────────────────────────────────────────────────

pub(crate) fn reader_pin() {
    this_cpu().active_readers.fetch_add(1, Ordering::Acquire);
}

pub(crate) fn reader_unpin() {
    this_cpu().active_readers.fetch_sub(1, Ordering::Release);
}

// ── Quiescence reporting ───────────────────────────────────────────

/// Declare a quiescent state on the current CPU. Stores the current
/// global epoch into this CPU's `last_quiescent` slot (monotonic) and
/// drains any locally-reclaimable deferred drops.
///
/// Safe no-op when a guard is still live on this CPU — advancing in
/// that case would allow reclamation under a live reader's feet.
pub fn report_quiescent() {
    let cell = this_cpu();
    if cell.active_readers.load(Ordering::Acquire) != 0 {
        return;
    }
    let now = GLOBAL_EPOCH.load(Ordering::Acquire);
    let prev = cell.last_quiescent.load(Ordering::Relaxed);
    // Either we're behind (`prev < now`, regular progress) or we started
    // at the sentinel `u64::MAX` ("inactive CPU") and are now active —
    // in which case we need to adopt the current epoch so
    // `all_cpus_past` tracks this CPU correctly.
    if prev == u64::MAX || now > prev {
        cell.last_quiescent.store(now, Ordering::Release);
    }
    drain_local_bucket(cell);
}

/// Open the next grace period if this CPU's defer bucket holds entries
/// the current epoch can never release. An entry retired at epoch `E`
/// is reclaimed only when `min_last_quiescent > E`, which requires a
/// LATER epoch to exist and every CPU to report quiescence under it —
/// but the scheduler's poll-boundary `report_quiescent` calls never bump
/// `GLOBAL_EPOCH`, so without this hook anything retired outside a
/// `sync()` would sit in its bucket forever. The executor calls this
/// once per round.
///
/// The bump is gated on this CPU having already reported quiescence for
/// the current epoch, so at most one new epoch is published per
/// completed local grace period (the `compare_exchange` loses harmlessly
/// when a peer CPU publishes first). No quiescent state is reported
/// here — draining still happens only at the executor's own (correctly
/// suppressed-on-preemption) `report_quiescent` boundaries.
pub fn advance_epoch_if_pending() {
    let cell = this_cpu();
    // IRQ-masked: `defer_raw` mutates this CPU's bucket from IRQ context.
    let pending = narf_lib::sync::without_interrupts(|| {
        // SAFETY: IRQs masked → sole accessor of this CPU's own bucket.
        unsafe { (*cell.bucket.get()).len }
    });
    if pending == 0 {
        return;
    }
    let now = GLOBAL_EPOCH.load(Ordering::Acquire);
    if cell.last_quiescent.load(Ordering::Acquire) >= now {
        let _ = GLOBAL_EPOCH.compare_exchange(now, now + 1, Ordering::AcqRel, Ordering::Relaxed);
    }
}

/// Declare that this CPU is going idle. Resets `last_quiescent` to
/// the `u64::MAX` "inactive" sentinel so subsequent `sync()` calls
/// don't wait on a CPU that may not poll again before its next
/// wake. The CPU will re-adopt the live epoch on its first
/// `report_quiescent` after wake. Drains the local bucket first so
/// any pending deferred drops are reclaimed before this CPU stops
/// reporting.
pub fn report_idle() {
    let cell = this_cpu();
    if cell.active_readers.load(Ordering::Acquire) != 0 {
        return;
    }
    drain_local_bucket(cell);
    cell.last_quiescent.store(u64::MAX, Ordering::Release);
}

// ── Deferred-drop enqueue / drain ───────────────────────────────────

pub(crate) fn defer_raw(ptr: *mut (), dropper: unsafe fn(*mut ())) {
    let epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
    let cell = this_cpu();
    // IRQ-masked: the per-CPU bucket is a lock-free `UnsafeCell`, but
    // `defer_raw` is reachable from BOTH task context and IRQ context (an
    // IRQ handler that drops an RCU-protected object defers it here), and
    // `drain_local_bucket` mutates the SAME bucket. An IRQ landing mid-push
    // — or a push landing mid-drain — tears a `DeferEntry`, leaving a
    // half-written `dropper` fn-pointer that `drain_local_bucket` then calls
    // (→ #UD on a garbage address). Masking IRQs around the only-this-CPU
    // mutation closes the same-CPU reentrancy window (cross-CPU is a non-issue
    // — each CPU owns its bucket). See the slab-magazine IRQ-safety precedent.
    narf_lib::sync::without_interrupts(|| {
        // SAFETY: IRQs masked, so this CPU is the sole accessor of its own
        // bucket for the duration of this mutation.
        let bucket = unsafe { &mut *cell.bucket.get() };
        if bucket.len < DEFER_BUCKET_CAP {
            bucket.slots[bucket.len] = DeferEntry {
                ptr,
                dropper: Some(dropper),
                epoch,
            };
            bucket.len += 1;
        } else {
            bucket.overflow += 1;
        }
    });
}

fn drain_local_bucket(cell: &CpuCell) {
    let min_q = min_last_quiescent();
    // Phase 1 — IRQ-masked: lift the grace-period-elapsed entries out of the
    // per-CPU bucket and compact what remains. Masking IRQs makes this CPU the
    // sole accessor of its lock-free `UnsafeCell` bucket; without it an IRQ
    // that calls `defer_raw` mid-compaction tears a `DeferEntry` and we'd later
    // call a half-written `dropper` fn-pointer (→ #UD). See `defer_raw`.
    //
    // Crucially we do NOT run the droppers under the mask: a dropper is
    // arbitrary `Drop` code that may be slow or re-enter `defer_raw` (deferring
    // a further drop), which must be free to take its own IRQ mask + push.
    let mut drained: [DeferEntry; DEFER_BUCKET_CAP] = [DeferEntry {
        ptr: core::ptr::null_mut(),
        dropper: None,
        epoch: 0,
    }; DEFER_BUCKET_CAP];
    let mut n = 0usize;
    narf_lib::sync::without_interrupts(|| {
        // SAFETY: IRQs masked → sole accessor of this CPU's own bucket.
        let bucket = unsafe { &mut *cell.bucket.get() };
        let mut write = 0;
        for read in 0..bucket.len {
            let entry = bucket.slots[read];
            if entry.epoch < min_q {
                drained[n] = entry;
                n += 1;
            } else {
                if write != read {
                    bucket.slots[write] = entry;
                }
                write += 1;
            }
        }
        bucket.len = write;
    });
    // Phase 2 — IRQs enabled: invoke the droppers on the lifted entries.
    for entry in drained.iter().take(n) {
        if let Some(f) = entry.dropper {
            // SAFETY: the pointer came from `Box::into_raw::<T>` via
            // `enqueue_drop`, and the grace period has elapsed: no reader is
            // viewing this allocation.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                f(entry.ptr);
            }
        }
    }
}

fn min_last_quiescent() -> u64 {
    let mut min = u64::MAX;
    for c in CPUS.iter() {
        let v = c.last_quiescent.load(Ordering::Acquire);
        if v < min {
            min = v;
        }
    }
    min
}

// ── sync() ──────────────────────────────────────────────────────────

/// Publish a new target epoch and loop until every CPU has crossed it.
pub fn sync_blocking() {
    let target = GLOBAL_EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    // Drive quiescence locally. Stage-2 single-CPU: we ARE the only CPU
    // so one pass suffices. A multi-CPU implementation would kick peers
    // to run their poll loop.
    let mut rounds = 0;
    loop {
        report_quiescent();
        if all_cpus_past(target) {
            break;
        }
        rounds += 1;
        // Bounded-grace-period discipline per spec §3.3. In Stage-2
        // single-CPU this only fires if a caller forgot to drop a
        // guard — we refuse to deadlock.
        if rounds > 8 {
            break;
        }
    }
    // Drain every CPU's bucket. Stage-2 single-CPU so this is just us.
    drain_local_bucket(this_cpu());
}

fn all_cpus_past(target: u64) -> bool {
    for c in CPUS.iter() {
        if c.last_quiescent.load(Ordering::Acquire) < target {
            return false;
        }
    }
    true
}

// ── async form of sync ──────────────────────────────────────────────

/// Future form of `sync()`. Yields between polls so a cooperative
/// executor can drive other tasks — each of whose polls will call
/// `report_quiescent()` at some point.
#[derive(Debug)]
pub struct SyncFuture {
    target: u64,
    pollcount: u32,
    published: bool,
}

impl SyncFuture {
    pub(crate) fn new() -> Self {
        Self {
            target: 0,
            pollcount: 0,
            published: false,
        }
    }
}

impl Future for SyncFuture {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if !this.published {
            this.target = GLOBAL_EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
            this.published = true;
        }
        // Outer poll itself is a quiescent moment on this CPU.
        report_quiescent();
        if all_cpus_past(this.target) {
            drain_local_bucket(this_cpu());
            return Poll::Ready(());
        }
        this.pollcount += 1;
        // Bounded-grace-period discipline (§3.3).
        if this.pollcount > 64 {
            drain_local_bucket(this_cpu());
            return Poll::Ready(());
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ── Diagnostics (test harness uses these) ───────────────────────────

/// Objects currently awaiting reclamation on this CPU.
pub fn deferred_len_this_cpu() -> usize {
    // SAFETY: same invariant as defer_raw.
    unsafe { (*this_cpu().bucket.get()).len }
}

/// Global epoch at this moment.
pub fn global_epoch() -> u64 {
    GLOBAL_EPOCH.load(Ordering::Acquire)
}

/// Number of enqueues discarded due to this CPU's bucket being full.
/// Non-zero = upgrade the per-CPU queue.
pub fn overflow_count_this_cpu() -> usize {
    // SAFETY: same invariant as defer_raw.
    unsafe { (*this_cpu().bucket.get()).overflow }
}
