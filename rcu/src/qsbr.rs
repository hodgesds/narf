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
//! - A **per-CPU intrusive deferred-drop list** stamped with the enqueue
//!   epoch, threaded through a header inside each managed allocation.
//!   Draining happens either in `sync()` or (Stage-3 main track) from
//!   a per-domain reclamation-worker Future.
//!
//! Scope (this crate):
//! - `all_cpus_past` is a real wait now that APs are up: peers cross the
//!   target epoch at their own poll boundaries, and an idle CPU
//!   publishes the `u64::MAX` "inactive" sentinel so it never holds a
//!   grace period open.
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

use crate::DeferHdr;

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
    /// Monotonic timestamp of the latest quiescent report. Zero denotes an
    /// inactive CPU and is ignored by stall detection.
    last_quiescent_ns: AtomicU64,
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
        last_quiescent_ns: AtomicU64::new(0),
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

// ── Deferred-drop per-CPU list ──────────────────────────────────────
//
// An INTRUSIVE singly-linked list, threaded through a `DeferHdr` that
// every RCU-managed allocation carries (see `crate::DeferNode`). This is
// Linux's `struct rcu_head` model, and it is here for Linux's reason: an
// object is retired from contexts that may not be able to allocate, so
// the list node must already exist. Enqueue is a two-store splice that
// cannot fail.
//
// It replaces a fixed 64-slot array that, on its 65th entry, incremented
// a counter and DROPPED THE POINTER ON THE FLOOR. That was a silent leak
// — the only evidence was `overflow_count_this_cpu()`, which nothing in
// the tree read — and it made any copy-on-write consumer (one retirement
// per publish) unsafe to write without a hand-rolled drain on the side.

struct DeferBucket {
    /// Head of this CPU's retirement list. Owned solely by this CPU.
    head: *mut DeferHdr,
    /// Nodes on the list. Kept because `advance_epoch_if_pending` asks
    /// "is anything pending" on every executor round and should not walk.
    len: usize,
}

impl DeferBucket {
    const fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
            len: 0,
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
    cell.last_quiescent_ns
        .store(narf_time::monotonic_ns(), Ordering::Release);
    drain_local_bucket(cell);
}

/// Return a bitmask of active CPUs whose latest QSBR quiescent report is at
/// least `threshold_ns` old. Inactive CPUs (timestamp zero) are omitted.
///
/// This is allocation-free and lock-free so a timer/fatal watchdog can query
/// it even when the stalled CPU holds an unrelated kernel lock.
pub fn stalled_cpu_mask(now_ns: u64, threshold_ns: u64) -> u64 {
    let mut mask = 0u64;
    for (cpu, cell) in CPUS.iter().enumerate().take(64) {
        let last = cell.last_quiescent_ns.load(Ordering::Acquire);
        if last != 0 && now_ns.saturating_sub(last) >= threshold_ns {
            mask |= 1u64 << cpu;
        }
    }
    mask
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
    cell.last_quiescent_ns.store(0, Ordering::Release);
}

// ── Deferred-drop enqueue / drain ───────────────────────────────────

/// Splice a retired node onto this CPU's reclamation list.
///
/// Allocation-free and infallible — the node's header was allocated with
/// the object it belongs to.
///
/// # Safety
/// `node` must point at the header of a live `crate::DeferNode<T>` that
/// has been unlinked from anywhere a new reader could reach it, and must
/// not already be on a list.
pub(crate) fn defer_node(node: *mut DeferHdr) {
    if node.is_null() {
        return;
    }
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
        // bucket for the duration of this mutation. The node is unreachable
        // to new readers, so writing its header races nothing.
        unsafe {
            let bucket = &mut *cell.bucket.get();
            (*node).epoch = epoch;
            (*node).next = bucket.head;
            bucket.head = node;
            bucket.len += 1;
        }
    });
}

fn drain_local_bucket(cell: &CpuCell) {
    let min_q = min_last_quiescent();
    // Phase 1 — IRQ-masked: DETACH the whole list. Masking makes this CPU
    // the sole accessor of its own `UnsafeCell` bucket; without it an IRQ
    // calling `defer_node` mid-walk would splice onto a head we are
    // simultaneously rewriting and one of the two nodes would be lost.
    //
    // Detaching wholesale, rather than walking in place, means an IRQ that
    // fires between phases simply starts a fresh list on the (now empty)
    // head — nothing to reconcile, and no entry can be dropped.
    let mut list = narf_lib::sync::without_interrupts(|| {
        // SAFETY: IRQs masked → sole accessor of this CPU's own bucket.
        unsafe {
            let bucket = &mut *cell.bucket.get();
            let head = bucket.head;
            bucket.head = core::ptr::null_mut();
            bucket.len = 0;
            head
        }
    });

    // Phase 2 — IRQs enabled: partition into reclaimable and still-waiting.
    // Pure pointer walking over nodes this CPU now owns exclusively; no
    // other CPU and no IRQ can see them, because they are off the bucket.
    let mut ready: *mut DeferHdr = core::ptr::null_mut();
    let mut keep: *mut DeferHdr = core::ptr::null_mut();
    let mut keep_len = 0usize;
    while !list.is_null() {
        // SAFETY: every node on this list was spliced on by `defer_node`
        // and is still live — nothing reclaims a node but this function,
        // and this CPU owns the detached list outright.
        let next = unsafe { (*list).next };
        // SAFETY: as above — a live node this CPU exclusively owns.
        let elapsed = unsafe { (*list).epoch } < min_q;
        let target = if elapsed { &mut ready } else { &mut keep };
        // SAFETY: as above — re-linking a node we exclusively own.
        unsafe {
            (*list).next = *target;
        }
        *target = list;
        if !elapsed {
            keep_len += 1;
        }
        list = next;
    }

    // Phase 3 — IRQ-masked: put the still-waiting nodes back, in front of
    // anything an IRQ pushed while phase 2 ran. Order within the list is
    // irrelevant: reclaimability is decided per node by its own epoch.
    if !keep.is_null() {
        narf_lib::sync::without_interrupts(|| {
            // SAFETY: IRQs masked → sole accessor of this CPU's own bucket.
            unsafe {
                let bucket = &mut *cell.bucket.get();
                // Walk to the end of `keep` and graft the bucket on, so
                // neither list is dropped.
                let mut tail = keep;
                while !(*tail).next.is_null() {
                    tail = (*tail).next;
                }
                (*tail).next = bucket.head;
                bucket.head = keep;
                bucket.len += keep_len;
            }
        });
    }

    // Phase 4 — IRQs enabled: run the droppers. Deliberately NOT under the
    // mask: a dropper is arbitrary `Drop` code that may be slow or re-enter
    // `defer_node` (retiring something further), which must be free to take
    // its own mask and splice.
    while !ready.is_null() {
        // SAFETY: the node's grace period has elapsed — every CPU reported
        // quiescence past its retirement epoch — so no reader is viewing it.
        // `dropper` was installed by `alloc_node` for this node's own `T`.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let next = (*ready).next;
            if let Some(f) = (*ready).dropper {
                f(ready);
            }
            ready = next;
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

/// Spec §3.3's first detection window: a CPU that has not reported
/// quiescence for this long starts incrementing [`stuck_quiescent_cpu`].
pub const STALL_WARN_NS: u64 = 100_000_000;

/// Per-CPU count of grace periods that waited past [`STALL_WARN_NS`] on
/// that CPU — spec §3.3's `stuck_quiescent_cpu`.
static STUCK_QUIESCENT_CPU: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Times a grace-period wait was refused because the CALLER held a live
/// read guard.
static SYNC_READER_HELD: AtomicU64 = AtomicU64::new(0);

/// Grace periods that waited past [`STALL_WARN_NS`] on `cpu`.
///
/// Non-zero means some CPU was slow to reach a poll boundary while a peer
/// waited on it. It is a latency signal, not a failure: the wait continues.
pub fn stuck_quiescent_cpu(cpu: usize) -> u64 {
    STUCK_QUIESCENT_CPU
        .get(cpu)
        .map(|c| c.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Times [`sync_blocking`] / [`sync_until`] returned without a grace
/// period because the caller was inside its own read critical section.
pub fn sync_reader_held_count() -> u64 {
    SYNC_READER_HELD.load(Ordering::Relaxed)
}

/// Publish a new target epoch and wait until every CPU has crossed it.
///
/// Waits for as long as that takes. It used to give up after eight
/// rounds — "we refuse to deadlock" — and return as though the grace
/// period had elapsed, which is the one outcome a reclamation primitive
/// may not produce: the caller frees on that word. Eight tight iterations
/// are nanoseconds, so on SMP the wait was over before any peer could
/// plausibly reach a poll boundary, and `sync()` degenerated into a
/// no-op whenever a peer was active. Single-CPU hid it — one pass really
/// did suffice, as the comment said.
///
/// Spec §3.3 is explicit that the bound is DETECTION, not an escape
/// hatch: its own pseudocode loops with no cap, and the counters exist
/// because "without detection, reclamation stalls indefinitely with no
/// visible symptom until memory pressure surfaces it". So this reports
/// and keeps waiting. The 1 s RCU stall watchdog in `frame/`'s timer
/// path — which already reads [`stalled_cpu_mask`] — is what turns a
/// genuine wedge into a dump, and owns the panic-or-continue policy.
///
/// The corollary is that a caller who cannot block indefinitely wants
/// [`sync_until`] or the async `sync_async`, and that blocking here with
/// interrupts masked defeats the watchdog that would have diagnosed it.
pub fn sync_blocking() {
    // With no deadline the only `false` [`sync_until`] can produce is the
    // guard-held refusal, which it has already counted and asserted.
    let _ = sync_until(u64::MAX);
}

/// [`sync_blocking`] with a deadline. Returns whether the grace period
/// actually elapsed — `false` means it did NOT, and nothing retired
/// before the call may be freed.
///
/// `deadline_ns` is an absolute `narf_time::monotonic_ns` value;
/// `u64::MAX` waits indefinitely.
#[must_use = "false means the grace period did NOT elapse"]
pub fn sync_until(deadline_ns: u64) -> bool {
    let cell = this_cpu();

    // A caller inside its own read critical section can never satisfy the
    // wait: `report_quiescent` deliberately no-ops while a guard is live,
    // so this CPU would never cross the target. Spec §3.3 forbids it
    // ("you may not `await` inside a read critical section"), and it is
    // the one case the old eight-round cap was really protecting against
    // — at the cost of silently truncating the wait for every correct
    // caller too. Refuse it by name instead.
    if cell.active_readers.load(Ordering::Acquire) != 0 {
        SYNC_READER_HELD.fetch_add(1, Ordering::Relaxed);
        debug_assert!(
            false,
            "rcu::sync() called while this CPU holds a live ReadGuard"
        );
        return false;
    }

    let target = GLOBAL_EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    let started_ns = narf_time::monotonic_ns();
    let mut warned = false;
    loop {
        // This CPU's own quiescent state is ours to declare; peers reach
        // theirs at their executor poll boundaries.
        report_quiescent();
        if all_cpus_past(target) {
            break;
        }

        let now = narf_time::monotonic_ns();
        if !warned && now.saturating_sub(started_ns) >= STALL_WARN_NS {
            warned = true;
            let mut stalled = stalled_cpu_mask(now, STALL_WARN_NS);
            while stalled != 0 {
                let cpu = stalled.trailing_zeros() as usize;
                stalled &= stalled - 1;
                STUCK_QUIESCENT_CPU[cpu].fetch_add(1, Ordering::Relaxed);
            }
        }
        if now >= deadline_ns {
            return false;
        }
        core::hint::spin_loop();
    }

    // Only this CPU's bucket: each CPU drains its own at its own quiescent
    // points, and reaching in would race the owner's `UnsafeCell`.
    drain_local_bucket(cell);
    true
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
        // No poll cap. Completing after 64 polls regardless told the
        // awaiting task its grace period had elapsed when it had not —
        // the same silent truncation `sync_blocking` carried, and this is
        // the form spec §3.3's pseudocode describes, which loops until
        // `all_cpus_past`. Unlike the blocking form this yields, so an
        // unsatisfied wait costs a re-poll rather than a wedged CPU, and
        // the executor keeps every other task running meanwhile.
        this.pollcount = this.pollcount.saturating_add(1);
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

// ── Diagnostics (test harness uses these) ───────────────────────────

/// Objects currently awaiting reclamation on this CPU.
pub fn deferred_len_this_cpu() -> usize {
    let cell = this_cpu();
    // IRQ-masked: `defer_node` mutates this CPU's bucket from IRQ context.
    narf_lib::sync::without_interrupts(|| {
        // SAFETY: IRQs masked → sole accessor of this CPU's own bucket.
        unsafe { (*cell.bucket.get()).len }
    })
}

/// Global epoch at this moment.
pub fn global_epoch() -> u64 {
    GLOBAL_EPOCH.load(Ordering::Acquire)
}

/// Test-only: a CPU's last reported quiescent epoch, or `u64::MAX` when
/// that CPU is inactive. Lets a smoke assert the invariant `sync()` is
/// supposed to establish — every CPU at or past the published target —
/// rather than just that it returned.
#[doc(hidden)]
pub fn __test_last_quiescent(cpu: usize) -> u64 {
    CPUS.get(cpu)
        .map(|c| c.last_quiescent.load(Ordering::Acquire))
        .unwrap_or(u64::MAX)
}

/// Number of enqueues discarded because this CPU's queue could not take
/// them. **Structurally always 0** since the queue became intrusive: the
/// list node is allocated with the object it belongs to, so `defer_node`
/// is a splice that cannot fail.
///
/// Retained as a standing regression assertion — a consumer that watches
/// this keeps compiling, and a non-zero reading would mean the intrusive
/// queue had regressed to something fallible.
pub fn overflow_count_this_cpu() -> usize {
    0
}
