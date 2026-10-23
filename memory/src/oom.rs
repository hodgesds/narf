//! Out-of-memory killer seam + async reaper.
//!
//! When the frame pool is exhausted and in-kernel reclaim (page-cache
//! shrinkers, the LRU sweep) cannot free enough, the last recourse is to
//! reclaim a userspace process's memory. The *policy* — which process to kill —
//! lives outside this crate: `memory` cannot enumerate tasks or deliver signals
//! without a dependency cycle. This module defines the [`OomKiller`] trait an
//! upper layer (or an out-of-tree crate) implements and registers via
//! [`register_oom_killer`], plus the async reaper that reclaims a chosen
//! victim's resident anonymous frames without waiting for it to schedule and
//! run its own exit teardown.
//!
//! # Soundness of cross-task reaping
//!
//! Reaping another task's page tables would be unsound if done naively. Three
//! invariants make [`AddressSpace::reap_anonymous`](crate::address_space::AddressSpace::reap_anonymous)
//! safe:
//!
//!   * The reaper holds an `Arc<AddressSpace>` (in [`OomVictim`]), so the
//!     last-`Arc` `Drop` teardown — which frees the same frames — cannot run
//!     concurrently. No double free.
//!   * No victim thread can be mid-fault on the same table while the reaper
//!     issues its shootdown. The scheduler maintains an explicit per-address-
//!     space live-task count: admission increments before publication and final
//!     slot drop decrements after the task can no longer run. Reaping waits for
//!     that count to reach zero. This is deliberately independent of `Arc`
//!     ownership, because passive kernel references pin lifetime without being
//!     able to fault or contend the IRQ-disabling region lock.
//!   * A forced full user-TLB shootdown lands before any frame is freed, so a
//!     CPU still momentarily running the doomed task cannot alias a reused
//!     frame through a stale entry (its next access simply re-faults).
//!
//! # Reaping only after the last task exits
//!
//! Every scheduler task attached to an address space contributes exactly one
//! live-task count, whether the address space is single-threaded or
//! `vm_shared`. SIGKILL propagates to all threads of a group, and final slot
//! drop retires each count. The zero transition wakes the dedicated reaper;
//! until then the victim remains queued without consuming its transient-lock
//! retry budget. The forced full cross-CPU shootdown flushes stale entries left
//! on CPUs where the dead task ran before any frame becomes reusable.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::address_space::AddressSpace;

/// A process the OOM policy selected to relieve memory pressure. The killer has
/// already initiated its death (e.g. queued SIGKILL); the `address_space`
/// handle lets the reaper reclaim its resident anonymous frames promptly, and
/// holding this `Arc` pins the address space so its `Drop` teardown cannot race
/// the reaper.
pub struct OomVictim {
    /// Process id (for logging / dedupe reporting).
    pub pid: u64,
    /// Thread id the kill was delivered to (dedupe key in the backlog).
    pub tid: u64,
    /// Resident pages at selection time — diagnostic only.
    pub rss_pages: usize,
    /// The victim's address space, pinned for the reaper.
    pub address_space: Arc<AddressSpace>,
    /// Remaining reaper passes this victim may be requeued for before it is
    /// abandoned to normal exit teardown. Decremented only for a transient
    /// region-lock collision after every victim task is quiescent; waiting for
    /// task exit is event-driven and does not consume this budget.
    pub retries_left: u32,
}

impl core::fmt::Debug for OomVictim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `AddressSpace` is not `Debug`; report identity + size instead.
        f.debug_struct("OomVictim")
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("rss_pages", &self.rss_pages)
            .field("retries_left", &self.retries_left)
            .finish_non_exhaustive()
    }
}

/// Result of one attempt to reap a victim's anonymous frames, so the reaper can
/// tell "made progress / nothing to do" apart from "temporarily can't and
/// should retry".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapOutcome {
    /// Reaped this many base pages (may be 0 if the AS was already reaped —
    /// idempotent). Terminal: the victim is dropped.
    Reaped(usize),
    /// Nothing reapable (empty / no root). Terminal: the victim is dropped.
    Nothing,
    /// Could not proceed WITHOUT losing soundness — the region lock's `try_lock`
    /// failed, or a victim task is still executable. The caller should requeue
    /// and retry after the appropriate event.
    Blocked,
}

/// Pluggable OOM policy. Implement this in a layer that can enumerate tasks and
/// deliver signals, then install it with [`register_oom_killer`]. An
/// out-of-tree crate can provide its own policy the same way.
pub trait OomKiller: Send + Sync {
    /// Select the highest-badness eligible victim, initiate its death (e.g.
    /// queue SIGKILL), and return it for asynchronous reaping. Returns `None`
    /// when nothing is eligible (only unkillable / kernel tasks remain).
    ///
    /// Called from the memory-pressure path: it must not allocate on the
    /// failure path and must not block.
    fn select_victim(&self) -> Option<OomVictim>;

    /// Select the highest-badness victim RESTRICTED to `pids` — the member set
    /// of a cgroup subtree that breached `memory.max`. Returns `None` when no
    /// listed pid is an eligible victim (the charge is then failed as ENOMEM
    /// rather than killing outside the offending cgroup, matching cgroup v2).
    /// The default ignores the filter for policies without cgroup awareness.
    fn select_victim_in(&self, _pids: &[u64]) -> Option<OomVictim> {
        self.select_victim()
    }
}

static OOM_KILLER: IrqSafeSpinLock<Option<&'static dyn OomKiller>> = IrqSafeSpinLock::new(None);

/// Global OOM-policy serialization, matching Linux's single `oom_lock` role.
/// Reclaim itself remains per-node, but only one worker may select and reap a
/// global victim at a time.
static OOM_SELECTION_ACTIVE: AtomicBool = AtomicBool::new(false);

struct OomSelectionGuard;

impl Drop for OomSelectionGuard {
    fn drop(&mut self) {
        OOM_SELECTION_ACTIVE.store(false, Ordering::Release);
    }
}

fn try_begin_oom_selection() -> Option<OomSelectionGuard> {
    OOM_SELECTION_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| OomSelectionGuard)
}

/// Bounded backlog of victims awaiting reaping. Pre-reserved at registration so
/// enqueue never allocates — freeing memory must not require allocating memory.
const REAP_BACKLOG: usize = 16;
static REAP_QUEUE: IrqSafeSpinLock<Option<VecDeque<OomVictim>>> = IrqSafeSpinLock::new(None);

/// Only one context may hold an in-flight victim outside the queue. Besides
/// making reaping match Linux's single oom_reaper shape, this reserves exactly
/// one extra deque slot for a blocked victim even if selection fills the
/// logical backlog while the pass is outside the lock.
static REAP_ACTIVE: AtomicBool = AtomicBool::new(false);

struct ReapGuard;

impl Drop for ReapGuard {
    fn drop(&mut self) {
        REAP_ACTIVE.store(false, Ordering::Release);
    }
}

fn try_begin_reap() -> Option<ReapGuard> {
    REAP_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| ReapGuard)
}

/// How many post-quiescence region-lock collisions may be retried before a
/// victim is abandoned to its normal exit teardown. Live tasks do not consume
/// this budget: their final scheduler detach wakes the reaper directly.
const REAP_MAX_RETRIES: u32 = 8;

/// Set while at least one victim is queued, so the reaper kthread knows to run.
static REAP_PENDING: AtomicBool = AtomicBool::new(false);

/// Set by a reap pass only when every victim task is quiescent but a transient
/// region-lock owner prevented progress. The persistent worker consumes this
/// bit and yields before retrying; a live victim instead waits for its final
/// scheduler detach event without spinning.
static REAP_RETRY_SOON: AtomicBool = AtomicBool::new(false);

/// Allocation-free wake seam for the upper-layer persistent OOM reaper task.
/// `memory` cannot depend on the scheduler/frame crates, so boot installs a
/// plain function pointer after preallocating the worker and its stack.
static REAPER_WAKE_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Count of victims abandoned to normal exit teardown after exhausting their
/// requeue budget (retry bound reached with no progress). Diagnostic only — a
/// nonzero value means some anonymous frames waited for the victim's own exit
/// instead of being reaped promptly. Never leaked silently: `reap_all` bumps
/// this on every abandonment and the reaper's driver surfaces it via
/// [`reap_abandoned_count`].
static REAP_ABANDONED: AtomicUsize = AtomicUsize::new(0);

/// Install the OOM policy and arm the reap backlog. Intended to be called once
/// at boot; last registration wins.
pub fn register_oom_killer(killer: &'static dyn OomKiller) {
    *OOM_KILLER.lock() = Some(killer);
    let mut q = REAP_QUEUE.lock();
    if q.is_none() {
        *q = Some(VecDeque::with_capacity(REAP_BACKLOG + 1));
    }
}

/// Install the wake hook for the boot-preallocated OOM reaper worker.
pub fn set_reaper_wake_hook(hook: fn()) {
    REAPER_WAKE_HOOK.store(hook as usize, Ordering::Release);
}

fn wake_reaper() {
    let p = REAPER_WAKE_HOOK.load(Ordering::Acquire);
    if p != 0 {
        // SAFETY: `p` came from a real static `fn()` in
        // `set_reaper_wake_hook` and registration is append-only at boot.
        let hook: fn() = unsafe { core::mem::transmute::<usize, fn()>(p) };
        hook();
    }
}

/// Wake the reaper only when a queued victim can benefit. Called by the
/// address-space live-task counter's one-to-zero transition.
pub(crate) fn wake_reaper_if_pending() {
    if REAP_PENDING.load(Ordering::Acquire) {
        wake_reaper();
    }
}

/// True once a policy is installed.
pub fn is_armed() -> bool {
    OOM_KILLER.lock().is_some()
}

/// Test-only: clear the installed OOM policy so a test's mock killer never
/// leaks into another test or the live kernel. Mirrors
/// [`reclaim::__reset_anon_reclaimer_for_test`](crate::reclaim::__reset_anon_reclaimer_for_test).
#[doc(hidden)]
pub fn __reset_oom_killer_for_test() {
    *OOM_KILLER.lock() = None;
}

/// Ask the installed policy to kill one victim and queue it for the reaper.
/// Returns the killed process's pid (for the caller to log a Linux-style
/// "Out of memory: Killed process N" line), or `None` if nothing was
/// eligible. Safe to call from the reclaim pump (executor context).
pub fn request_oom_relief() -> Option<u64> {
    let selection = try_begin_oom_selection()?;
    let killed = request_oom_relief_unserialized();
    drop(selection);
    if killed.is_some() {
        wake_reaper();
    }
    killed
}

fn request_oom_relief_unserialized() -> Option<u64> {
    // `&'static dyn OomKiller` is Copy, so this drops the registry lock before
    // calling into the (possibly allocating) policy.
    let killer = (*OOM_KILLER.lock())?;
    enqueue_victim(killer.select_victim()?)
}

/// Re-check global allocation viability, select at most one victim, and drain
/// its queued pages while holding the global OOM-selection gate. A competing
/// node returns `None`; a later allocation failure can retry after this pass.
pub fn request_oom_relief_and_reap_if(still_needed: fn() -> bool) -> Option<u64> {
    let selection = try_begin_oom_selection()?;
    if !still_needed() {
        return None;
    }
    let killed = request_oom_relief_unserialized();
    let _ = reap_all();
    drop(selection);
    if killed.is_some() || reap_pending() {
        wake_reaper();
    }
    killed
}

/// Cgroup-scoped variant: kill one victim chosen ONLY from `pids` (a cgroup
/// subtree that breached `memory.max`). Returns the killed pid, or `None` when
/// no listed pid is eligible — in which case the caller fails the charge as
/// ENOMEM rather than killing outside the offending cgroup (cgroup v2 semantics).
pub fn request_oom_relief_in(pids: &[u64]) -> Option<u64> {
    let selection = try_begin_oom_selection()?;
    let killer = (*OOM_KILLER.lock())?;
    let killed = enqueue_victim(killer.select_victim_in(pids)?);
    drop(selection);
    wake_reaper();
    killed
}

mod selection_gate_tests {
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::try_begin_oom_selection;

    fn smoke_oom_selection_gate_serializes_and_releases() -> TestResult {
        let Some(first) = try_begin_oom_selection() else {
            return TestResult::Fail("OOM selection gate unexpectedly busy");
        };
        if try_begin_oom_selection().is_some() {
            return TestResult::Fail("concurrent OOM selection was admitted");
        }
        drop(first);
        if try_begin_oom_selection().is_none() {
            return TestResult::Fail("OOM selection gate did not release");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "memory/oom",
        smoke_oom_selection_gate_serializes_and_releases
    );
}

/// Queue a selected victim for the async reaper and return its pid. Shared by
/// the global and cgroup-scoped OOM entry points.
fn enqueue_victim(mut victim: OomVictim) -> Option<u64> {
    let pid = victim.pid;
    let tid = victim.tid;
    // Seed the transient-lock retry budget here (not in the policy). Waiting
    // for the final task detach is event-driven and does not decrement it.
    victim.retries_left = REAP_MAX_RETRIES;
    let mut q = REAP_QUEUE.lock();
    if let Some(queue) = q.as_mut() {
        // Dedupe by tid so repeated pressure ticks don't stack the same
        // victim; drop silently if the bounded backlog is full (the victim's
        // own exit teardown still reclaims it). `push` stays within the
        // reserved capacity, so it never reallocates.
        if !queue.iter().any(|v| v.tid == tid) && queue.len() < REAP_BACKLOG {
            queue.push_back(victim);
            REAP_PENDING.store(true, Ordering::Release);
        }
    }
    Some(pid)
}

/// True when the reaper has queued work.
pub fn reap_pending() -> bool {
    REAP_PENDING.load(Ordering::Acquire)
}

/// Number of victims abandoned to normal exit teardown after their requeue
/// budget was exhausted (diagnostic / test accessor).
pub fn reap_abandoned_count() -> usize {
    REAP_ABANDONED.load(Ordering::Acquire)
}

/// Consume a request for a cooperative retry. This is set only for a reaper
/// collision or a post-quiescence region-lock collision, never merely because
/// a victim task remains alive.
pub fn take_reap_retry_request() -> bool {
    REAP_RETRY_SOON.swap(false, Ordering::AcqRel)
}

/// Reap every queued victim, freeing its resident anonymous frames. Returns the
/// number of base pages reclaimed. Driven by a dedicated reaper kthread from a
/// safe (non-IRQ, no-locks-held) context; each victim's `Arc` is released as it
/// is processed, so if the reaper held the last reference the remaining teardown
/// (page tables, root) completes in `Drop`.
///
/// A victim with live scheduler tasks is requeued WITHOUT spending its retry
/// budget and is revisited when final task detach wakes the worker. Once tasks
/// are quiescent, a transient region-lock collision decrements the bounded
/// retry budget and requests a cooperative retry. Only exhaustion of that
/// post-quiescence budget abandons the victim to normal exit teardown.
///
/// Allocation-free: it processes only the victims present when the pass starts
/// (a length snapshot), popping each from the front and pushing a still-blocked
/// victim to the back of the same pre-reserved `VecDeque`. Both operations are
/// O(1), and the extra reserved slot covers the sole serialized in-flight
/// victim, so freeing memory never allocates.
pub fn reap_all() -> usize {
    let Some(_reap) = try_begin_reap() else {
        // The persistent worker will yield and retry after the current pass
        // releases its in-flight victim.
        REAP_RETRY_SOON.store(true, Ordering::Release);
        return 0;
    };
    let mut total = 0;
    let mut retry_soon = false;
    // Snapshot how many victims to process this pass. Blocked victims we push
    // back land beyond this count and are left for the next pass, so a single
    // call can't spin on the same still-blocked victim.
    let mut remaining = {
        let q = REAP_QUEUE.lock();
        q.as_ref().map_or(0, |queue| queue.len())
    };
    while remaining > 0 {
        remaining -= 1;
        // Pop one victim from the front in O(1). Reaping itself runs outside
        // the queue lock (it takes address-space + shootdown locks).
        let mut victim = {
            let mut q = REAP_QUEUE.lock();
            match q.as_mut() {
                Some(queue) => match queue.pop_front() {
                    Some(victim) => victim,
                    None => break,
                },
                _ => break,
            }
        };
        // Passive Arc owners are irrelevant to execution liveness. Only the
        // scheduler-maintained task count proves whether a user can still fault
        // or enter a VMA critical section through this root.
        if !victim.address_space.user_tasks_quiesced() {
            let mut q = REAP_QUEUE.lock();
            if let Some(queue) = q.as_mut() {
                debug_assert!(queue.len() < queue.capacity());
                queue.push_back(victim);
            }
            continue;
        }
        match victim.address_space.reap_anonymous_owned() {
            ReapOutcome::Reaped(pages) => total += pages,
            ReapOutcome::Nothing => {}
            ReapOutcome::Blocked => {
                // Re-check liveness because a task publication racing the first
                // observation must be treated as event-driven task wait, not as
                // a transient lock collision. Valid scheduler lifecycles do not
                // attach after zero, but this keeps the gate fail-closed.
                if !victim.address_space.user_tasks_quiesced() {
                    let mut q = REAP_QUEUE.lock();
                    if let Some(queue) = q.as_mut() {
                        debug_assert!(queue.len() < queue.capacity());
                        queue.push_back(victim);
                    }
                    continue;
                }
                // Every task is quiescent, so Blocked means `try_lock` met a
                // transient passive kernel owner. Retry cooperatively with a
                // bounded budget rather than spinning under this call.
                if victim.retries_left > 0 {
                    victim.retries_left -= 1;
                    let mut q = REAP_QUEUE.lock();
                    if let Some(queue) = q.as_mut() {
                        debug_assert!(queue.len() < queue.capacity());
                        queue.push_back(victim);
                        retry_soon = true;
                    }
                } else {
                    // Retry budget spent. Account it (never a silent leak — the
                    // reaper's driver surfaces this via `reap_abandoned_count`)
                    // and let `victim` drop; its own exit teardown still
                    // reclaims the frames.
                    REAP_ABANDONED.fetch_add(1, Ordering::AcqRel);
                }
            }
        }
        // `victim` (and its Arc) drops here for the reaped/nothing/abandoned
        // cases; a requeued victim was moved back into the queue above.
    }
    // Leave REAP_PENDING set iff victims (requeued blockers) remain.
    let still_queued = {
        let q = REAP_QUEUE.lock();
        let pending = q.as_ref().is_some_and(|queue| !queue.is_empty());
        REAP_PENDING.store(pending, Ordering::Release);
        pending
    };
    if retry_soon && still_queued {
        REAP_RETRY_SOON.store(true, Ordering::Release);
    }
    total
}

/// Test-support hooks for the in-kernel `memory` suite (see
/// `crate::tests`). These drive the reap queue directly so a test can exercise
/// the requeue / bounded-retry / vm_shared paths without registering a global
/// policy (which would clobber the boot-installed one). They are `pub(crate)`
/// so only the memory crate's own always-compiled test module can reach them.
/// The reaper smokes that consume them are x86_64-only, so the module is gated
/// to match (it is otherwise dead code on aarch64).
#[cfg(target_arch = "x86_64")]
pub(crate) mod test_support {
    use super::*;

    /// Arm the reap queue (idempotent) so tests can enqueue without registering
    /// a real [`OomKiller`].
    pub(crate) fn arm_queue() {
        let mut q = REAP_QUEUE.lock();
        if q.is_none() {
            *q = Some(VecDeque::with_capacity(REAP_BACKLOG + 1));
        }
    }

    /// The reaper's retry bound, so tests can iterate exactly to exhaustion.
    pub(crate) const MAX_RETRIES: u32 = REAP_MAX_RETRIES;

    /// Drop every queued victim and clear the pending flag, isolating a test
    /// from any leftover state. Returns the number of victims discarded.
    pub(crate) fn drain_queue() -> usize {
        let mut q = REAP_QUEUE.lock();
        let n = q.as_mut().map_or(0, |queue| queue.len());
        if let Some(queue) = q.as_mut() {
            queue.clear();
        }
        REAP_PENDING.store(false, Ordering::Release);
        REAP_RETRY_SOON.store(false, Ordering::Release);
        n
    }

    /// Enqueue a victim with the standard retry budget, mirroring
    /// [`request_oom_relief`] minus the policy call. Returns `true` if it was
    /// queued (deduped by tid; dropped if the bounded backlog is full).
    pub(crate) fn enqueue(mut victim: OomVictim) -> bool {
        victim.retries_left = REAP_MAX_RETRIES;
        let tid = victim.tid;
        let mut q = REAP_QUEUE.lock();
        if let Some(queue) = q.as_mut() {
            if !queue.iter().any(|v| v.tid == tid) && queue.len() < REAP_BACKLOG {
                queue.push_back(victim);
                REAP_PENDING.store(true, Ordering::Release);
                return true;
            }
        }
        false
    }

    /// Current number of queued victims (test observability).
    pub(crate) fn queued_len() -> usize {
        let q = REAP_QUEUE.lock();
        q.as_ref().map_or(0, |queue| queue.len())
    }

    /// Snapshot the abandoned-victim counter so a test can measure its own delta
    /// (the counter is process-global and monotonic).
    pub(crate) fn abandoned_count() -> usize {
        REAP_ABANDONED.load(Ordering::Acquire)
    }
}
