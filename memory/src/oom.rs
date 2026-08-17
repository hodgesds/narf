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
//!   * It reaps only single-threaded (`!vm_shared`) victims and takes the
//!     region lock with `try_lock`, so no sibling thread can be mid-fault on
//!     the same table and no CPU is spinning on that lock while the reaper
//!     issues its shootdown.
//!   * A forced full user-TLB shootdown lands before any frame is freed, so a
//!     CPU still momentarily running the doomed task cannot alias a reused
//!     frame through a stale entry (its next access simply re-faults).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

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
}

impl core::fmt::Debug for OomVictim {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `AddressSpace` is not `Debug`; report identity + size instead.
        f.debug_struct("OomVictim")
            .field("pid", &self.pid)
            .field("tid", &self.tid)
            .field("rss_pages", &self.rss_pages)
            .finish_non_exhaustive()
    }
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

/// Set while at least one victim is queued, so the reaper kthread knows to run.
static REAP_PENDING: AtomicBool = AtomicBool::new(false);

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

/// Ask the installed policy to kill one victim and queue it for the reaper.
/// Returns the killed process's pid (for the caller to log a Linux-style
/// "Out of memory: Killed process N" line), or `None` if nothing was
/// eligible. Safe to call from the reclaim pump (executor context).
pub fn request_oom_relief() -> Option<u64> {
    // `&'static dyn OomKiller` is Copy, so this drops the registry lock before
    // calling into the (possibly allocating) policy.
    let killer = (*OOM_KILLER.lock())?;
    let victim = killer.select_victim()?;
    let pid = victim.pid;
    let tid = victim.tid;
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

/// Reap every queued victim, freeing its resident anonymous frames. Returns the
/// number of base pages reclaimed. Driven by a dedicated reaper kthread from a
/// safe (non-IRQ, no-locks-held) context; each victim's `Arc` is released as it
/// is processed, so if the reaper held the last reference the remaining teardown
/// (page tables, root) completes in `Drop`.
pub fn reap_all() -> usize {
    let mut total = 0;
    loop {
        // Pop one victim under the queue lock; `pop` keeps the reserved
        // capacity so future enqueues stay allocation-free. Reaping itself runs
        // outside the queue lock (it takes address-space + shootdown locks).
        let victim = {
            let mut q = REAP_QUEUE.lock();
            match q.as_mut().and_then(|queue| queue.pop()) {
                Some(v) => v,
                None => {
                    REAP_PENDING.store(false, Ordering::Release);
                    break;
                }
            }
        };
        total += victim.address_space.reap_anonymous();
        // `victim` (and its Arc) drops here.
    }
    total
}
