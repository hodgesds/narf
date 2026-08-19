//! Durable, per-fd readiness with a lost-wake-free wait primitive.
//!
//! # The bug class this eliminates
//!
//! The classic poll/epoll lost-wakeup race is *check readiness → (data
//! arrives here) → register waker → sleep forever*. NARF historically closed
//! it only by convention (a global generation counter re-checked after
//! registering) backed by a ~10 ms fallback tick, and it split a file's
//! readiness across three separate, drift-prone `FileOps` methods
//! (`poll_readiness` level, `poll_edge_token` edge, `readiness_notifies` a
//! hand-maintained "do I even wake anyone" boolean). Any one of them getting
//! out of sync is a lost wake or a busy-spin.
//!
//! [`Readiness`] makes the whole class **unrepresentable**:
//!
//! * The waiter set is **private**. The only way to register a waker is
//!   [`Readiness::arm`], which *always* checks the level first, under the
//!   lock. You cannot register without checking — the racy shape does not
//!   compile.
//! * [`Readiness::set`] — the only mutator — bumps the edge sequence and wakes
//!   every intersecting waiter **under the same lock**. So arm-vs-set is
//!   serialized: either `set` wins and `arm` observes the new level (→
//!   `Ready`), or `arm` wins and `set` wakes it. No wake is ever lost, by
//!   construction — no fallback tick required.
//! * Waking is *intrinsic* to every state change, not an opt-in flag, so a
//!   file physically cannot change readiness without notifying its waiters.
//!   The `readiness_notifies` mismatch class ceases to exist.
//! * Level (`mask`) and edge (`seq`) move together inside the one `set`, so
//!   they cannot drift.
//!
//! # Durability of the wake itself
//!
//! `set` fires each satisfied waiter with [`Waker::wake_by_ref`], *under* the
//! lock, and never removes a waiter. In NARF the park waker's `wake_by_ref` is
//! the Linux `try_to_wake_up` op: an atomic runnable-bit store plus a
//! lock-free reschedule IPI, touching no allocation. So the wake is durable
//! and IRQ-safe even when `set` runs from a device-IRQ readiness source — it
//! drops no `Arc` (a `WakeCell` dealloc, illegal in IRQ) and deadlocks against
//! no lock; Linux likewise wakes under the wait-queue lock. A woken waiter
//! stays registered until the task's re-arm (which replaces it, or returns
//! `Ready` and removes it) or its [`disarm`] on exit; a redundant re-fire is
//! an idempotent runnable-bit store. `Readiness` stays waker-agnostic and only
//! ever calls `wake_by_ref` — never a dropping `wake`.

extern crate alloc;

use alloc::collections::BTreeMap;
use core::task::{Poll, Waker};

use crate::sync::IrqSafeSpinLock;

/// One registered waiter: the readiness bits it cares about, and the waker to
/// fire when any of them become set.
struct Waiter {
    interest: u32,
    waker: Waker,
}

struct Inner {
    /// Current level: the OR of the readiness bits presently satisfied. The
    /// bit meanings (`POLL_IN`/`POLL_OUT`/…) are the caller's; `Readiness`
    /// treats `mask` as an opaque bitset.
    mask: u32,
    /// Monotonic edge counter, bumped on every rising edge. Edge-triggered
    /// consumers snapshot it and compare; it can never be behind `mask`
    /// because both move under the same lock in [`Readiness::set`].
    seq: u64,
    /// Registered waiters, keyed by a caller-chosen id (a task id in the
    /// kernel) so a re-arm from the same waiter *replaces* rather than
    /// accumulates. PRIVATE: [`Readiness::arm`] is the only inserter, and it
    /// always checks `mask` first.
    waiters: BTreeMap<u64, Waiter>,
}

/// A durable readiness cell owned by a blocking file/socket/pipe/etc.
pub struct Readiness {
    inner: IrqSafeSpinLock<Inner>,
}

impl core::fmt::Debug for Readiness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let g = self.inner.lock();
        f.debug_struct("Readiness")
            .field("mask", &g.mask)
            .field("seq", &g.seq)
            .field("waiters", &g.waiters.len())
            .finish()
    }
}

impl Readiness {
    /// A cell whose initial level is `mask` and with no waiters.
    #[must_use]
    pub const fn new(mask: u32) -> Self {
        Readiness {
            inner: IrqSafeSpinLock::new(Inner {
                mask,
                seq: 0,
                waiters: BTreeMap::new(),
            }),
        }
    }

    /// Current level (the OR of satisfied readiness bits).
    #[must_use]
    pub fn mask(&self) -> u32 {
        self.inner.lock().mask
    }

    /// Current monotonic edge sequence.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.inner.lock().seq
    }

    /// The ONLY state mutator. Sets `add` bits, clears `clear` bits; on any
    /// *rising* edge (a bit in the new level that was not set before) bumps
    /// `seq` and wakes every waiter whose `interest` intersects the new level.
    /// `clear`-only transitions (readiness going away) touch neither `seq` nor
    /// waiters — a poller waits for readiness to *appear*, never to leave.
    pub fn set(&self, add: u32, clear: u32) {
        let mut g = self.inner.lock();
        let old = g.mask;
        let new = (old & !clear) | add;
        g.mask = new;
        let rising = new & !old;
        if rising == 0 {
            return;
        }
        g.seq = g.seq.wrapping_add(1);
        // Wake every satisfied waiter BY REFERENCE, UNDER the lock. This is the
        // end-to-end durable, IRQ-safe wake:
        //
        // * `wake_by_ref` is the Linux-TTWU op — an atomic runnable-bit store
        //   plus a lock-free reschedule IPI (`resched_remote`). It touches no
        //   allocation and takes no lock, so calling it under this spinlock
        //   neither deadlocks nor drops an `Arc` — the latter being illegal
        //   from an IRQ-context readiness source (a `Sleepable`/`WakeCell`
        //   dealloc). Linux likewise wakes under the wait-queue lock.
        // * Waiters are NOT removed here. Removing would drop the waker's
        //   `Arc<WakeCell>`, the very IRQ-illegal dealloc we must avoid. A woken
        //   waiter is instead cleared by the task's re-arm ([`arm`] replaces by
        //   id, and a now-satisfied re-arm returns `Ready` which removes it) or
        //   by its [`disarm`] on exit. A still-registered, already-woken waiter
        //   is harmless: a later rising edge simply re-stores its runnable bit.
        for w in g.waiters.values() {
            if w.interest & new != 0 {
                w.waker.wake_by_ref();
            }
        }
    }

    /// The ONLY wait primitive, and the reason the lost-wake race is
    /// unrepresentable. Atomically, under the lock:
    ///
    /// * if `mask & interest != 0` → return [`Poll::Ready`] with the satisfied
    ///   bits (no waiter is left registered);
    /// * else register (or replace) this waiter under `id` and return
    ///   [`Poll::Pending`].
    ///
    /// A [`set`](Self::set) racing this call is serialized by the same lock, so
    /// a readiness edge in the check→register window is never missed: `set`
    /// either ran first (and `arm` observes it here) or runs next (and finds
    /// this waiter to wake).
    #[must_use = "a Pending arm means the caller must park; a Ready arm carries the revents"]
    pub fn arm(&self, id: u64, interest: u32, waker: &Waker) -> Poll<u32> {
        let mut g = self.inner.lock();
        let ready = g.mask & interest;
        if ready != 0 {
            // Satisfied now: do not register — nothing to wake later.
            g.waiters.remove(&id);
            return Poll::Ready(ready);
        }
        g.waiters.insert(
            id,
            Waiter {
                interest,
                waker: waker.clone(),
            },
        );
        Poll::Pending
    }

    /// Remove any waiter registered under `id`. Called when a wait ends for a
    /// reason other than this cell (timeout, EINTR, the fd leaving the set, or
    /// task exit) so a stale waker is never fired.
    pub fn disarm(&self, id: u64) {
        self.inner.lock().waiters.remove(&id);
    }

    /// Number of currently-registered waiters. Diagnostics/tests only.
    #[must_use]
    pub fn waiter_count(&self) -> usize {
        self.inner.lock().waiters.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};
    use core::task::{RawWaker, RawWakerVTable, Waker};

    // A host-test waker that counts how many times it was woken, via an
    // Arc<AtomicU32> smuggled through the RawWaker data pointer. This mirrors
    // the kernel's shape (wake() = a cheap side effect on a shared cell) while
    // being observable in a `#[test]`.
    fn counting_waker(counter: &Arc<AtomicU32>) -> Waker {
        fn clone(p: *const ()) -> RawWaker {
            // SAFETY: `p` is an Arc<AtomicU32> raw pointer we created below.
            let arc = unsafe { Arc::from_raw(p as *const AtomicU32) };
            let cloned = arc.clone();
            let _ = Arc::into_raw(arc); // don't drop the original
            RawWaker::new(Arc::into_raw(cloned) as *const (), &VTABLE)
        }
        fn wake(p: *const ()) {
            // SAFETY: consumes one ref (the Waker's), incrementing the counter.
            let arc = unsafe { Arc::from_raw(p as *const AtomicU32) };
            arc.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(p: *const ()) {
            // SAFETY: borrows without consuming.
            let arc = unsafe { Arc::from_raw(p as *const AtomicU32) };
            arc.fetch_add(1, Ordering::SeqCst);
            let _ = Arc::into_raw(arc);
        }
        fn drop_fn(p: *const ()) {
            // SAFETY: drops the Waker's ref.
            unsafe { drop(Arc::from_raw(p as *const AtomicU32)) };
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_fn);
        let raw = Arc::into_raw(counter.clone()) as *const ();
        // SAFETY: `raw` + VTABLE form a valid RawWaker per the fns above.
        unsafe { Waker::from_raw(RawWaker::new(raw, &VTABLE)) }
    }

    const IN: u32 = 1;
    const OUT: u32 = 2;

    #[test]
    fn arm_then_set_wakes_no_lost_wakeup() {
        let r = Readiness::new(0);
        let n = Arc::new(AtomicU32::new(0));
        let w = counting_waker(&n);
        // Not ready → parks.
        assert_eq!(r.arm(1, IN, &w), Poll::Pending);
        assert_eq!(r.waiter_count(), 1);
        // The edge arrives AFTER we registered: the durable case.
        r.set(IN, 0);
        assert_eq!(
            n.load(Ordering::SeqCst),
            1,
            "set must wake the armed waiter"
        );
        assert_eq!(
            r.waiter_count(),
            1,
            "set is drop-free: the woken waiter is kept"
        );
        // The level is now visible; re-arm returns Ready and clears the entry.
        assert_eq!(r.arm(1, IN, &w), Poll::Ready(IN));
        assert_eq!(
            r.waiter_count(),
            0,
            "re-arm on Ready clears the registration"
        );
    }

    #[test]
    fn set_then_arm_returns_ready_never_parks() {
        let r = Readiness::new(0);
        let n = Arc::new(AtomicU32::new(0));
        let w = counting_waker(&n);
        // The edge arrives BEFORE anyone parks: the other side of the race.
        r.set(IN, 0);
        assert_eq!(r.arm(1, IN, &w), Poll::Ready(IN), "must observe the level");
        assert_eq!(r.waiter_count(), 0, "Ready must not leave a registration");
    }

    #[test]
    fn interest_is_respected_no_spurious_wake() {
        let r = Readiness::new(0);
        let n = Arc::new(AtomicU32::new(0));
        let w = counting_waker(&n);
        assert_eq!(r.arm(1, OUT, &w), Poll::Pending); // waiting for OUT
        r.set(IN, 0); // an IN edge must NOT wake an OUT-only waiter
        assert_eq!(n.load(Ordering::SeqCst), 0);
        assert_eq!(r.waiter_count(), 1);
        r.set(OUT, 0); // the OUT edge does
        assert_eq!(n.load(Ordering::SeqCst), 1);
        assert_eq!(r.waiter_count(), 1, "drop-free: the woken waiter is kept");
    }

    #[test]
    fn set_is_drop_free_and_keeps_waiter() {
        // `set` must NEVER remove/drop a waiter — dropping the waker's Arc is an
        // IRQ-illegal dealloc. The woken waiter stays registered (and re-fires
        // on a later edge) until `disarm` clears it in task context.
        let r = Readiness::new(0);
        let n = Arc::new(AtomicU32::new(0));
        let w = counting_waker(&n);
        assert_eq!(r.arm(1, IN, &w), Poll::Pending);
        r.set(IN, 0);
        assert_eq!(r.waiter_count(), 1, "set keeps the waiter");
        // A later rising edge (after a clear) re-fires the SAME kept waiter —
        // an idempotent runnable-bit store, harmless.
        r.set(0, IN); // clear (no wake, no bump)
        r.set(IN, 0); // rise again
        assert_eq!(
            n.load(Ordering::SeqCst),
            2,
            "kept waiter re-fires on next edge"
        );
        // Only disarm (task context) removes it.
        r.disarm(1);
        assert_eq!(r.waiter_count(), 0);
        r.set(0, IN);
        r.set(IN, 0);
        assert_eq!(
            n.load(Ordering::SeqCst),
            2,
            "disarmed waiter never fires again"
        );
    }

    #[test]
    fn rearm_same_id_dedups() {
        let r = Readiness::new(0);
        let n = Arc::new(AtomicU32::new(0));
        let w = counting_waker(&n);
        assert_eq!(r.arm(7, IN, &w), Poll::Pending);
        assert_eq!(r.arm(7, IN, &w), Poll::Pending); // same id replaces
        assert_eq!(r.waiter_count(), 1, "re-arm must not accumulate");
        r.set(IN, 0);
        assert_eq!(n.load(Ordering::SeqCst), 1, "woken exactly once");
    }

    #[test]
    fn seq_bumps_only_on_rising_edge() {
        let r = Readiness::new(0);
        assert_eq!(r.seq(), 0);
        r.set(IN, 0);
        assert_eq!(r.seq(), 1);
        r.set(IN, 0); // already set: no rising edge, no bump
        assert_eq!(r.seq(), 1);
        r.set(0, IN); // clearing: no bump
        assert_eq!(r.seq(), 1);
        r.set(IN, 0); // rising again
        assert_eq!(r.seq(), 2);
    }

    #[test]
    fn disarm_prevents_stale_wake() {
        let r = Readiness::new(0);
        let n = Arc::new(AtomicU32::new(0));
        let w = counting_waker(&n);
        assert_eq!(r.arm(1, IN, &w), Poll::Pending);
        r.disarm(1);
        assert_eq!(r.waiter_count(), 0);
        r.set(IN, 0);
        assert_eq!(n.load(Ordering::SeqCst), 0, "disarmed waiter must not fire");
    }
}
