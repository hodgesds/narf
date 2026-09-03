//! Durable, per-fd readiness with a lost-wake-free wait primitive.
//!
//! # The bug class this eliminates
//!
//! The classic poll/epoll lost-wakeup race is *check readiness → (data
//! arrives here) → register waker → sleep forever*. NARF historically closed
//! it only by convention (a global generation counter re-checked after
//! registering) backed by a ~10 ms fallback tick, and it split a file's
//! readiness across separate, drift-prone `FileOps` methods (`poll_readiness`
//! level plus a per-provider edge token, and `readiness_notifies` a
//! hand-maintained "do I even wake anyone" boolean). Any one of them getting
//! out of sync is a lost wake or a busy-spin.
//!
//! [`Readiness`] makes the whole class **unrepresentable**:
//!
//! * The waiter set is **private**. The only ways to register a waker are
//!   [`Readiness::arm`] and [`Readiness::arm_exclusive`], which *always* check
//!   the level first, under the lock. You cannot register without checking —
//!   the racy shape does not compile.
//! * [`Readiness::set`] and its event/wake-all variants bump the edge sequence
//!   and wake every intersecting ordinary waiter plus the oldest intersecting
//!   exclusive waiter **under the same lock**. So arm-vs-set is serialized:
//!   either `set` wins and `arm` observes the new level (→ `Ready`), or `arm`
//!   wins and `set` wakes it. No wake is ever lost, by construction — no
//!   fallback tick required. Exclusive waiters mirror Linux pipe wait queues
//!   and prevent a one-token pipe event from waking a whole reader herd.
//! * Waking is *intrinsic* to every state change, not an opt-in flag, so a
//!   file physically cannot change readiness without notifying its waiters.
//!   The `readiness_notifies` mismatch class ceases to exist.
//! * Level (`mask`) and edge (`seq`) move together inside the one `set`, so
//!   they cannot drift.
//!
//! # Durability of the wake itself
//!
//! `set` fires satisfied waiters with [`Waker::wake_by_ref`], *under* the lock,
//! and never drops a waiter. In NARF the park waker's `wake_by_ref` is
//! the Linux `try_to_wake_up` op: an atomic runnable-bit store plus a
//! lock-free reschedule IPI, touching no allocation. So the wake is durable
//! and IRQ-safe even when `set` runs from a device-IRQ readiness source — it
//! drops no `Arc` (a `WakeCell` dealloc, illegal in IRQ) and deadlocks against
//! no lock; Linux likewise wakes under the wait-queue lock. A woken ordinary
//! waiter stays eligible until the task's re-arm or [`disarm`]; a woken
//! exclusive waiter stays stored but is dequeued until re-arm, which is the
//! drop-free equivalent of Linux's autoremove wake function. `Readiness` stays
//! waker-agnostic and only ever calls `wake_by_ref` — never a dropping `wake`.

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use core::task::{Poll, Waker};

use crate::sync::IrqSafeSpinLock;

/// One registered waiter: the readiness bits it cares about, and the waker to
/// fire when any of them become set.
struct Waiter {
    interest: u32,
    waker: Waker,
    /// Linux `WQ_FLAG_EXCLUSIVE`: wake at most one such waiter for an event.
    exclusive: bool,
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
    /// accumulates. PRIVATE: the arm methods are the only inserters, and they
    /// always check `mask` first.
    waiters: BTreeMap<u64, Waiter>,
    /// FIFO of exclusive waiter ids which have not yet been selected. Waking
    /// pops the selected id but retains its `Waiter`, avoiding a waker drop in
    /// IRQ context. Re-arm puts the id back at the tail, matching Linux's
    /// exclusive wait-queue fairness.
    exclusive_order: VecDeque<u64>,
}

impl Inner {
    /// Remove an id from the exclusive FIFO. This runs only from arm/disarm in
    /// task context; the readiness event path never shrinks or reallocates the
    /// FIFO.
    fn remove_exclusive_id(&mut self, id: u64) {
        self.exclusive_order.retain(|queued| *queued != id);
    }

    /// Linux wait-queue wake policy: notify every non-exclusive observer (poll
    /// and epoll) followed by at most one exclusive blocking-I/O waiter.
    fn wake_waiters(&mut self, bits: u32) {
        for waiter in self.waiters.values() {
            if !waiter.exclusive && waiter.interest & bits != 0 {
                waiter.waker.wake_by_ref();
            }
        }

        // Rotate non-matching exclusive waiters without exceeding the FIFO's
        // existing length/capacity, so this path cannot allocate in IRQ
        // context. Stale entries are discarded defensively.
        let queued = self.exclusive_order.len();
        for _ in 0..queued {
            let Some(id) = self.exclusive_order.pop_front() else {
                break;
            };
            let Some(waiter) = self.waiters.get(&id) else {
                continue;
            };
            if !waiter.exclusive {
                continue;
            }
            if waiter.interest & bits != 0 {
                waiter.waker.wake_by_ref();
                return;
            }
            self.exclusive_order.push_back(id);
        }
    }

    /// Terminal-state wake policy: notify every waiter, including all
    /// exclusive blockers, while retaining their allocation-bearing wakers.
    fn wake_all_waiters(&mut self, bits: u32) {
        for waiter in self.waiters.values() {
            if waiter.interest & bits != 0 {
                waiter.waker.wake_by_ref();
            }
        }

        // Logically dequeue only the exclusive waiters selected by this wake.
        // Rotate unmatched entries without growing the queue, so the IRQ path
        // neither allocates nor drops a waker. Stale entries are discarded.
        let queued = self.exclusive_order.len();
        for _ in 0..queued {
            let Some(id) = self.exclusive_order.pop_front() else {
                break;
            };
            let keep = self
                .waiters
                .get(&id)
                .is_some_and(|waiter| waiter.exclusive && waiter.interest & bits == 0);
            if keep {
                self.exclusive_order.push_back(id);
            }
        }
    }
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
                exclusive_order: VecDeque::new(),
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

    /// Set `add` bits and clear `clear` bits. On any
    /// *rising* edge (a bit in the new level that was not set before) bumps
    /// `seq`, wakes every ordinary waiter whose `interest` intersects the new
    /// level, and wakes the oldest one intersecting exclusive waiter.
    /// `clear`-only transitions (readiness going away) touch neither `seq` nor
    /// waiters — a poller waits for readiness to *appear*, never to leave.
    pub fn set(&self, add: u32, clear: u32) {
        self.set_event(add, clear, 0);
    }

    /// Publish a readiness level plus one provider event atomically. A rising
    /// level or nonzero currently-ready `event` bumps `seq` and performs one
    /// wake operation. This represents Linux providers such as pipes which
    /// notify poll waiters on a same-level write after `poll_usage` is set,
    /// without selecting two exclusive blockers for a single operation when
    /// that write also creates a rising edge.
    pub fn set_event(&self, add: u32, clear: u32, event: u32) {
        let mut g = self.inner.lock();
        let old = g.mask;
        let new = (old & !clear) | add;
        g.mask = new;
        let rising = new & !old;
        let ready_event = event & new;
        if rising == 0 && ready_event == 0 {
            return;
        }
        g.seq = g.seq.wrapping_add(1);
        // Wake satisfied waiters BY REFERENCE, UNDER the lock. This is the
        // end-to-end durable, IRQ-safe wake:
        //
        // * `wake_by_ref` is the Linux-TTWU op — an atomic runnable-bit store
        //   plus a lock-free reschedule IPI (`resched_remote`). It touches no
        //   allocation and takes no lock, so calling it under this spinlock
        //   neither deadlocks nor drops an `Arc` — the latter being illegal
        //   from an IRQ-context readiness source (a `Sleepable`/`WakeCell`
        //   dealloc). Linux likewise wakes under the wait-queue lock.
        // * Waiters are NOT dropped here. Removing would drop the waker's
        //   `Arc<WakeCell>`, the very IRQ-illegal dealloc we must avoid. An
        //   exclusive waiter is removed only from the u64 FIFO, leaving its
        //   waker stored until task-context re-arm/disarm.
        g.wake_waiters(if rising != 0 { new } else { ready_event });
    }

    /// Publish a level transition and wake every matching waiter on a rising
    /// edge, including all exclusive blockers. This is reserved for terminal
    /// state such as the final peer of a pipe closing: every sleeper must run
    /// to observe EOF or `EPIPE`, matching Linux `wake_up_interruptible_all`.
    pub fn set_wake_all(&self, add: u32, clear: u32) {
        let mut g = self.inner.lock();
        let old = g.mask;
        let new = (old & !clear) | add;
        g.mask = new;
        if new & !old == 0 {
            return;
        }
        g.seq = g.seq.wrapping_add(1);
        g.wake_all_waiters(new);
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
        self.arm_with_mode(id, interest, waker, false)
    }

    /// Atomically check readiness and, when not ready, enqueue a Linux-style
    /// exclusive waiter. Each matching event wakes all ordinary/persistent
    /// observers but only the oldest exclusive waiter. The selected waiter is
    /// logically dequeued without dropping its waker; re-arm places it at the
    /// FIFO tail and [`disarm`](Self::disarm) removes it completely.
    #[must_use = "a Pending arm means the caller must park; a Ready arm carries the revents"]
    pub fn arm_exclusive(&self, id: u64, interest: u32, waker: &Waker) -> Poll<u32> {
        self.arm_with_mode(id, interest, waker, true)
    }

    fn arm_with_mode(&self, id: u64, interest: u32, waker: &Waker, exclusive: bool) -> Poll<u32> {
        let mut g = self.inner.lock();
        let ready = g.mask & interest;
        if ready != 0 {
            // Satisfied now: do not register — nothing to wake later.
            g.remove_exclusive_id(id);
            g.waiters.remove(&id);
            return Poll::Ready(ready);
        }
        g.remove_exclusive_id(id);
        g.waiters.insert(
            id,
            Waiter {
                interest,
                waker: waker.clone(),
                exclusive,
            },
        );
        if exclusive {
            g.exclusive_order.push_back(id);
        }
        Poll::Pending
    }

    /// Register a PERSISTENT waiter — the Linux `eppoll_entry` model: the waker
    /// stays in the wait queue for the fd's whole lifetime in the poll set and
    /// is NEVER removed on readiness. Unlike [`arm`](Self::arm), a satisfied
    /// level does not consume the registration: the same waker keeps firing on
    /// every future [`set`](Self::set)/[`notify`](Self::notify) until an explicit
    /// [`disarm`](Self::disarm). Returns the currently-satisfied bits
    /// (`mask & interest`) so the caller can seed an initial edge WITHOUT
    /// dropping the registration. This is what lets epoll's per-fd ready-list
    /// waker capture events between `epoll_wait` calls (including non-parking
    /// `timeout==0` polls) — a one-shot [`arm`](Self::arm) would be gone by the
    /// time the next event fired.
    pub fn arm_persistent(&self, id: u64, interest: u32, waker: &Waker) -> u32 {
        let mut g = self.inner.lock();
        g.remove_exclusive_id(id);
        g.waiters.insert(
            id,
            Waiter {
                interest,
                waker: waker.clone(),
                exclusive: false,
            },
        );
        g.mask & interest
    }

    /// Signal an EVENT on `bits` — a Linux wait-queue wakeup. Bumps `seq` and
    /// wakes every ordinary waiter and the oldest one exclusive waiter whose
    /// interest intersects `bits`, UNCONDITIONALLY:
    /// unlike [`set`](Self::set), it does not gate on a rising level edge and
    /// does not touch `mask`. This is what makes the epoll ready-list capture
    /// events the level cannot represent — a follow-up write on an already
    /// `POLL_IN` ring, or a new connection on an already-pending listener —
    /// exactly as Linux wakes its wait queue on every such event. Used at the
    /// real I/O event sites; the level-reconcile path stays on `set` (rising-
    /// edge-gated) so a passive re-sync never spuriously fires. `bits == 0` is
    /// a no-op. Retires the per-provider edge token, whose only job was to
    /// carry these same-level events.
    pub fn notify(&self, bits: u32) {
        if bits == 0 {
            return;
        }
        let mut g = self.inner.lock();
        g.seq = g.seq.wrapping_add(1);
        g.wake_waiters(bits);
    }

    /// Remove any waiter registered under `id`. Called when a wait ends for a
    /// reason other than this cell (timeout, EINTR, the fd leaving the set, or
    /// task exit) so a stale waker is never fired.
    pub fn disarm(&self, id: u64) {
        let mut g = self.inner.lock();
        g.remove_exclusive_id(id);
        g.waiters.remove(&id);
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
    fn exclusive_wake_is_one_at_a_time_fifo_and_keeps_observers() {
        let r = Readiness::new(0);
        let first = Arc::new(AtomicU32::new(0));
        let second = Arc::new(AtomicU32::new(0));
        let observer = Arc::new(AtomicU32::new(0));
        let first_waker = counting_waker(&first);
        let second_waker = counting_waker(&second);
        let observer_waker = counting_waker(&observer);

        assert_eq!(r.arm_exclusive(10, IN, &first_waker), Poll::Pending);
        assert_eq!(r.arm_exclusive(20, IN, &second_waker), Poll::Pending);
        assert_eq!(r.arm(30, IN, &observer_waker), Poll::Pending);

        r.set(IN, 0);
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 0);
        assert_eq!(observer.load(Ordering::SeqCst), 1);

        // The selected waiter re-arms at the tail after consuming the event.
        r.set(0, IN);
        assert_eq!(r.arm_exclusive(10, IN, &first_waker), Poll::Pending);
        r.set(IN, 0);
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 1);
        assert_eq!(observer.load(Ordering::SeqCst), 2);

        r.set(0, IN);
        assert_eq!(r.arm_exclusive(20, IN, &second_waker), Poll::Pending);
        r.set(IN, 0);
        assert_eq!(first.load(Ordering::SeqCst), 2);
        assert_eq!(second.load(Ordering::SeqCst), 1);
        assert_eq!(observer.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn notify_selects_next_exclusive_without_dropping_wakers() {
        let r = Readiness::new(0);
        let first = Arc::new(AtomicU32::new(0));
        let second = Arc::new(AtomicU32::new(0));
        let observer = Arc::new(AtomicU32::new(0));

        assert_eq!(
            r.arm_exclusive(1, IN, &counting_waker(&first)),
            Poll::Pending
        );
        assert_eq!(
            r.arm_exclusive(2, IN, &counting_waker(&second)),
            Poll::Pending
        );
        r.arm_persistent(3, IN, &counting_waker(&observer));

        r.notify(IN);
        r.notify(IN);
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 1);
        assert_eq!(observer.load(Ordering::SeqCst), 2);
        assert_eq!(
            r.waiter_count(),
            3,
            "IRQ-safe wake must retain every stored waker"
        );
    }

    #[test]
    fn set_event_performs_one_exclusive_wake_per_operation() {
        let r = Readiness::new(0);
        let first = Arc::new(AtomicU32::new(0));
        let second = Arc::new(AtomicU32::new(0));
        let observer = Arc::new(AtomicU32::new(0));

        assert_eq!(
            r.arm_exclusive(1, IN, &counting_waker(&first)),
            Poll::Pending
        );
        assert_eq!(
            r.arm_exclusive(2, IN, &counting_waker(&second)),
            Poll::Pending
        );
        r.arm_persistent(3, IN, &counting_waker(&observer));

        // One operation both raises the level and carries an event. It must
        // not select one exclusive waiter for each representation.
        r.set_event(IN, 0, IN);
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 0);
        assert_eq!(observer.load(Ordering::SeqCst), 1);

        // A later same-level operation selects the next exclusive waiter.
        r.set_event(IN, 0, IN);
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 1);
        assert_eq!(observer.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn terminal_transition_wakes_all_exclusive_waiters() {
        let r = Readiness::new(0);
        let first = Arc::new(AtomicU32::new(0));
        let second = Arc::new(AtomicU32::new(0));
        let observer = Arc::new(AtomicU32::new(0));

        assert_eq!(
            r.arm_exclusive(1, IN, &counting_waker(&first)),
            Poll::Pending
        );
        assert_eq!(
            r.arm_exclusive(2, IN, &counting_waker(&second)),
            Poll::Pending
        );
        assert_eq!(r.arm(3, IN, &counting_waker(&observer)), Poll::Pending);

        r.set_wake_all(IN, 0);
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 1);
        assert_eq!(observer.load(Ordering::SeqCst), 1);
        assert_eq!(r.waiter_count(), 3, "wake-all must remain drop-free");

        // Exclusive waiters were logically dequeued by the terminal wake.
        r.notify(IN);
        assert_eq!(first.load(Ordering::SeqCst), 1);
        assert_eq!(second.load(Ordering::SeqCst), 1);
        assert_eq!(observer.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn wake_all_preserves_unmatched_exclusive_waiters() {
        let r = Readiness::new(0);
        let reader = Arc::new(AtomicU32::new(0));
        let writer = Arc::new(AtomicU32::new(0));

        assert_eq!(
            r.arm_exclusive(1, IN, &counting_waker(&reader)),
            Poll::Pending
        );
        assert_eq!(
            r.arm_exclusive(2, OUT, &counting_waker(&writer)),
            Poll::Pending
        );

        r.set_wake_all(IN, 0);
        assert_eq!(reader.load(Ordering::SeqCst), 1);
        assert_eq!(writer.load(Ordering::SeqCst), 0);

        // The unrelated terminal transition must not silently dequeue the
        // writer; a later matching event still selects it.
        r.notify(OUT);
        assert_eq!(reader.load(Ordering::SeqCst), 1);
        assert_eq!(writer.load(Ordering::SeqCst), 1);
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
