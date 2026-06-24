//! Deferred-wake queue.
//!
//! IRQ handlers that want to wake parked async tasks (timer ticks,
//! IRQ vector wakers) can't call `Waker::wake()` directly: wake()
//! consumes the Waker, which drops the inner Arc — if that's the
//! last reference, the slab dealloc trips the alloc-context check
//! (`memory::context::is_sleepable` returns false while
//! `narf_lib::context::in_irq` is true).
//!
//! Instead, IRQ handlers `push_pending(wakers)` here and the
//! scheduler's idle path calls `drain_and_wake` from non-IRQ
//! context. The queue is a fixed-size stash; overflow is dropped
//! (a missed wake is recoverable — the next timer tick re-fires
//! the still-pending wheel slot).
//!
//! Per-CPU storage avoids cross-CPU contention. Bounded size means
//! no allocation in IRQ context.

use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::Waker;

use crate::sync::IrqSafeSpinLock;

/// Max wakers stashed per CPU. 64 matches `timer_wheel::MAX_SLEEPERS`
/// — one full wheel drain can fit without overflow. Bursts beyond
/// that are recoverable: the wake source (timer tick) re-fires on
/// the next deadline; missed wakers stay parked until then.
const MAX_PENDING: usize = 64;

/// Per-CPU pending-wake slot array. Indexed by `current_cpu()`.
/// Bounded by `MAX_CPUS` from `crate::percpu`.
const N_CPUS: usize = crate::percpu::MAX_CPUS;

struct Queue {
    /// Wakers waiting to be woken outside IRQ context.
    slots: [Option<Waker>; MAX_PENDING],
}

impl Queue {
    const fn new() -> Self {
        Self {
            slots: [const { None }; MAX_PENDING],
        }
    }
}

static QUEUES: [IrqSafeSpinLock<Queue>; N_CPUS] = {
    const Q: IrqSafeSpinLock<Queue> = IrqSafeSpinLock::new(Queue::new());
    [Q; N_CPUS]
};

/// Diagnostic: total wakers that overflowed (lost). Surfaced for
/// debugging — non-zero suggests sleep deadlines are firing
/// faster than the idle path drains them.
pub static OVERFLOWED_WAKERS: AtomicUsize = AtomicUsize::new(0);

/// Diagnostic: total wakers successfully queued.
pub static QUEUED_WAKERS: AtomicUsize = AtomicUsize::new(0);

/// Diagnostic: total wakers drained (i.e. wake() called on them).
pub static DRAINED_WAKERS: AtomicUsize = AtomicUsize::new(0);

/// Push wakers onto the current CPU's pending queue. Safe to call
/// from IRQ context — uses bounded array, no allocation. Overflow
/// silently drops (counted in `OVERFLOWED_WAKERS`).
pub fn push_pending<I: IntoIterator<Item = Option<Waker>>>(wakers: I) {
    push_pending_iter(wakers.into_iter().flatten());
}

/// Lower-level: push wakers from an iterator that yields `Waker`
/// directly (not `Option<Waker>`). Used by `dispatch::on_irq`
/// which drains a `Vec<Waker>` and shouldn't pay the Option wrap.
pub fn push_pending_iter<I: IntoIterator<Item = Waker>>(wakers: I) {
    let cpu = crate::percpu::current_cpu();
    let cpu = if cpu < N_CPUS { cpu } else { 0 };
    let mut q = QUEUES[cpu].lock();
    for w in wakers {
        let mut placed = false;
        for slot in q.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(w);
                QUEUED_WAKERS.fetch_add(1, Ordering::Relaxed);
                placed = true;
                break;
            }
        }
        if !placed {
            OVERFLOWED_WAKERS.fetch_add(1, Ordering::Relaxed);
            // `w` drops here — IRQ context. Dropping a Waker
            // calls drop_raw which decrements the Arc. If that's
            // the last reference, this trips the same panic the
            // queue is meant to avoid. In practice the overflow
            // path is rare (need >64 simultaneous expired
            // sleepers); peer SleepUntils hold the Arc above
            // refcount=1 in the common case. If real-HW boots
            // overflow, bump MAX_PENDING.
        }
    }
}

/// Non-destructive, LOCK-FREE: are there wakers queued but not yet drained?
/// Two relaxed atomic loads — cheap enough for the 1000 Hz timer-preempt hot
/// path to ask "would yielding to the executor service pending work?". The
/// counters are global (not per-CPU); on a single-CPU build that's exact, and
/// a cross-CPU false positive only costs one extra (harmless) preempt.
pub fn has_pending() -> bool {
    QUEUED_WAKERS.load(Ordering::Relaxed) != DRAINED_WAKERS.load(Ordering::Relaxed)
}

/// Drain this CPU's pending queue and call wake() on each. Must
/// be called from non-IRQ context (the scheduler's
/// `run_until_empty` idle path is the canonical caller).
///
/// Returns the number woken.
pub fn drain_and_wake() -> usize {
    let cpu = crate::percpu::current_cpu();
    let cpu = if cpu < N_CPUS { cpu } else { 0 };
    // Take the array out under the lock, then drop the lock
    // before calling wake() — wake() may itself want to register
    // a new pending entry (re-entrant scheduling), and the lock
    // we'd be holding is on the per-CPU queue.
    let mut taken: [Option<Waker>; MAX_PENDING] = [const { None }; MAX_PENDING];
    {
        let mut q = QUEUES[cpu].lock();
        for (i, slot) in q.slots.iter_mut().enumerate() {
            taken[i] = slot.take();
        }
    }
    let mut n = 0usize;
    for w in taken.into_iter().flatten() {
        w.wake();
        n += 1;
    }
    DRAINED_WAKERS.fetch_add(n, Ordering::Relaxed);
    n
}
