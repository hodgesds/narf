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
//!   * No sibling thread can be mid-fault on the same table while the reaper
//!     issues its shootdown. This holds trivially for a single-threaded
//!     (`!vm_shared`) victim, and for a formerly-multithreaded (`vm_shared`)
//!     victim once *every* sibling thread has exited — see below. The region
//!     table is taken with `try_lock`, so no CPU is spinning on that lock while
//!     the reaper's forced shootdown waits for acks (which would deadlock).
//!   * A forced full user-TLB shootdown lands before any frame is freed, so a
//!     CPU still momentarily running the doomed task cannot alias a reused
//!     frame through a stale entry (its next access simply re-faults).
//!
//! # Reaping a formerly-multithreaded (`vm_shared`) victim
//!
//! A `vm_shared` address space can be resident on several CPUs at once while
//! its threads run, so reaping it out from under a *live* sibling would be
//! unsound (a sibling could be mid-fault installing a PTE the reaper is tearing
//! down). But a SIGKILL propagates to ALL threads of the group, and each thread
//! holds its own `Arc<AddressSpace>` clone (in its scheduler slot) that is
//! dropped synchronously when the thread finishes its exit poll. Once the LAST
//! thread has exited, no scheduler slot references the AS any more, so the only
//! remaining clone is the one the reaper pinned in [`OomVictim`]. The reaper
//! detects that state with `Arc::strong_count(&victim.address_space) == 1`: a
//! count of one proves there is no other live holder — no sibling thread can be
//! running or mid-fault — so the AS is effectively single-owner and reaping is
//! safe. The forced full cross-CPU shootdown still runs first, flushing any
//! stale entry left on a CPU a now-dead thread last ran on. A victim whose
//! count is still `> 1` (a thread has not finished exiting yet) is requeued and
//! retried on a later pass rather than reaped early.

use alloc::sync::Arc;
use alloc::vec::Vec;
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
    /// abandoned to normal exit teardown. Decremented each time the reaper
    /// cannot make progress (region lock held, or a `vm_shared` sibling has not
    /// finished exiting). `select_victim` leaves this at 0; the queue seeds it
    /// (see [`REAP_MAX_RETRIES`]) on enqueue.
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
    /// failed, or the AS is `vm_shared` with a sibling thread still exiting. The
    /// caller should requeue and retry on a later pass.
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
}

static OOM_KILLER: IrqSafeSpinLock<Option<&'static dyn OomKiller>> = IrqSafeSpinLock::new(None);

/// Bounded backlog of victims awaiting reaping. Pre-reserved at registration so
/// enqueue never allocates — freeing memory must not require allocating memory.
const REAP_BACKLOG: usize = 16;
static REAP_QUEUE: IrqSafeSpinLock<Option<Vec<OomVictim>>> = IrqSafeSpinLock::new(None);

/// How many reaper passes a victim may be requeued for before it is abandoned
/// to its own exit teardown. Covers a transiently-held region lock and a
/// `vm_shared` group whose last thread has not finished exiting; a handful of
/// passes is enough for either to clear without spinning the reaper.
const REAP_MAX_RETRIES: u32 = 8;

/// Set while at least one victim is queued, so the reaper kthread knows to run.
static REAP_PENDING: AtomicBool = AtomicBool::new(false);

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
        *q = Some(Vec::with_capacity(REAP_BACKLOG));
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
    // `&'static dyn OomKiller` is Copy, so this drops the registry lock before
    // calling into the (possibly allocating) policy.
    let killer = (*OOM_KILLER.lock())?;
    let mut victim = killer.select_victim()?;
    let pid = victim.pid;
    let tid = victim.tid;
    // Seed the requeue budget here (not in the policy): a victim whose region
    // lock is transiently held, or whose last `vm_shared` sibling has not yet
    // finished exiting, is retried on later reaper passes instead of dropped.
    victim.retries_left = REAP_MAX_RETRIES;
    let mut q = REAP_QUEUE.lock();
    if let Some(queue) = q.as_mut() {
        // Dedupe by tid so repeated pressure ticks don't stack the same
        // victim; drop silently if the bounded backlog is full (the victim's
        // own exit teardown still reclaims it). `push` stays within the
        // reserved capacity, so it never reallocates.
        if !queue.iter().any(|v| v.tid == tid) && queue.len() < queue.capacity() {
            queue.push(victim);
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

/// Reap every queued victim, freeing its resident anonymous frames. Returns the
/// number of base pages reclaimed. Driven by a dedicated reaper kthread from a
/// safe (non-IRQ, no-locks-held) context; each victim's `Arc` is released as it
/// is processed, so if the reaper held the last reference the remaining teardown
/// (page tables, root) completes in `Drop`.
///
/// A victim the reaper cannot make progress on this pass — its region lock is
/// transiently held (`try_lock` failed), or it is a `vm_shared` group with a
/// sibling thread still exiting (`Arc::strong_count > 1`) — is REQUEUED with a
/// decremented retry budget rather than dropped, so a later pass retries it.
/// Only once the budget is exhausted is it abandoned to its own exit teardown
/// (and accounted in [`reap_abandoned_count`]), so a transient obstruction
/// never silently strands the victim's frames.
///
/// Allocation-free: it processes only the victims present when the pass starts
/// (a length snapshot), popping each from the FRONT and pushing a still-blocked,
/// budget-decremented victim to the BACK of the same pre-reserved queue — so it
/// never re-examines a requeued victim within one pass and never grows the
/// backing store. Freeing memory must not require allocating memory.
pub fn reap_all() -> usize {
    let mut total = 0;
    // Snapshot how many victims to process this pass. Blocked victims we push
    // back land beyond this count and are left for the next pass, so a single
    // call can't spin on the same still-blocked victim.
    let mut remaining = {
        let q = REAP_QUEUE.lock();
        q.as_ref().map_or(0, |queue| queue.len())
    };
    while remaining > 0 {
        remaining -= 1;
        // Pop one victim from the FRONT under the queue lock; `remove(0)` keeps
        // the reserved capacity so the queue never reallocates. Reaping itself
        // runs outside the queue lock (it takes address-space + shootdown locks).
        let mut victim = {
            let mut q = REAP_QUEUE.lock();
            match q.as_mut() {
                Some(queue) if !queue.is_empty() => queue.remove(0),
                _ => break,
            }
        };
        // A count of 1 means the reaper's own `Arc` is the sole remaining
        // clone: no scheduler slot references the AS, so no thread (single- or
        // multi-threaded) is live on it — reaping is safe even if it was once
        // `vm_shared`. See the module doc.
        let sole_owner = Arc::strong_count(&victim.address_space) == 1;
        match victim.address_space.reap_anonymous_owned(sole_owner) {
            ReapOutcome::Reaped(pages) => total += pages,
            ReapOutcome::Nothing => {}
            ReapOutcome::Blocked => {
                // Couldn't make progress (lock held, or a `vm_shared` sibling
                // still exiting). Requeue with a decremented budget, or abandon
                // it once the budget is spent.
                if victim.retries_left > 0 {
                    victim.retries_left -= 1;
                    let mut q = REAP_QUEUE.lock();
                    if let Some(queue) = q.as_mut() {
                        // Push to the BACK, within the reserved capacity (this
                        // victim just came off the same bounded queue, so there
                        // is room). Never reallocates.
                        if queue.len() < queue.capacity() {
                            queue.push(victim);
                        }
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
        q.as_ref().map_or(0, |queue| queue.len())
    };
    REAP_PENDING.store(still_queued > 0, Ordering::Release);
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
            *q = Some(Vec::with_capacity(REAP_BACKLOG));
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
            if !queue.iter().any(|v| v.tid == tid) && queue.len() < queue.capacity() {
                queue.push(victim);
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
