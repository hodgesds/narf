//! Async `Mutex<T>` — futures-friendly mutual exclusion driven by
//! the scheduler waker.
//!
//! Spec: `lib/specification/spec.md` §3.1 (Mutex/RwLock — Stage-2
//! item). Drivers that need to await while holding logical
//! ownership of a resource (I2C bus, HID report queue, USB
//! transfer descriptor) cannot use `IrqSafeSpinLock` — that lock
//! disables IRQs for the entire critical section, so any `.await`
//! inside would deadlock the executor's own timer/IRQ wakes.
//!
//! Design: a single `IrqSafeSpinLock` protects `{ locked: bool,
//! waiters: VecDeque<(WaiterId, Waker)> }`. Acquire path: if
//! `locked == false`, take it and return `Ready`; otherwise push
//! our `(id, waker)` (or update the waker if we already have a
//! slot) and return `Pending`. Release path (guard `Drop`): pop
//! one waiter from the front, wake it. FIFO is the simplest
//! fairness model that doesn't starve.
//!
//! No spin-wait for "lock probably about to free up" — drivers
//! should reach for `IrqSafeSpinLock` when sub-microsecond
//! contention dominates and for `Mutex<T>` when the critical
//! section involves I/O, allocation, or any other code that may
//! suspend.

extern crate alloc;

use alloc::collections::VecDeque;
use core::cell::UnsafeCell;
use core::fmt;
use core::future::Future;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use crate::sync::IrqSafeSpinLock;

/// Monotonic identifier for a parked `LockFuture`. Distinguishes
/// our entry in `waiters` from other futures that happen to clone
/// the same `Waker`. Wraps after 2^64 lock attempts (≈ 600 years
/// at 10^9 acquires/sec).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct WaiterId(u64);

static NEXT_WAITER_ID: AtomicU64 = AtomicU64::new(1);

fn next_waiter_id() -> WaiterId {
    WaiterId(NEXT_WAITER_ID.fetch_add(1, Ordering::Relaxed))
}

/// Async-aware mutual exclusion. `lock()` returns a future that
/// resolves to a `MutexGuard` when the lock becomes available.
/// Waiters are served FIFO.
pub struct Mutex<T: ?Sized> {
    inner: IrqSafeSpinLock<MutexInner>,
    data: UnsafeCell<T>,
}

struct MutexInner {
    locked: bool,
    waiters: VecDeque<(WaiterId, Waker)>,
    /// Linux `MUTEX_FLAG_HANDOFF`: the waiter at the front has been woken
    /// once and found the lock taken by someone who never queued. The next
    /// release hands the lock to it directly instead of freeing it.
    handoff: bool,
    /// The waiter a release handed the lock to, which owns it from that
    /// moment (`locked` stays true) and claims it on its next poll.
    granted: Option<WaiterId>,
}

// SAFETY: `Mutex<T>` provides exclusive access to `T` through the
// guard, the same contract as `std::sync::Mutex`. `T: Send` is
// sufficient to share the mutex across tasks.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
// SAFETY: exclusive access is serialized by the lock; `T: Send` makes sharing the guarded value across tasks sound.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

/// [`Mutex::held_state`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldState {
    /// Held, by a guard or by a grant not yet claimed.
    pub locked: bool,
    /// The waiter (its id) a release handed the lock to, which has not run
    /// to claim it yet.
    pub granted_to: Option<u64>,
    /// Futures queued for the lock.
    pub waiters: usize,
}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            inner: IrqSafeSpinLock::new(MutexInner {
                locked: false,
                waiters: VecDeque::new(),
                handoff: false,
                granted: None,
            }),
            data: UnsafeCell::new(data),
        }
    }

    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Returns a future that resolves to a `MutexGuard` when the
    /// lock is available.
    #[inline]
    #[track_caller]
    pub fn lock(&self) -> LockFuture<'_, T> {
        LockFuture {
            mutex: self,
            waiter_id: None,
            site: core::panic::Location::caller(),
        }
    }

    /// Non-blocking attempt to acquire. Returns `None` immediately
    /// if the lock is held.
    #[inline]
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        let mut inner = self.inner.lock();
        if inner.locked {
            return None;
        }
        inner.locked = true;
        Some(MutexGuard { mutex: self })
    }

    /// Acquire only when free and no waiter remains queued. Optional
    /// optimistic spinners use this to avoid bypassing queued sleepers.
    /// Failure neither enrolls a waiter nor changes wake ownership.
    #[inline]
    pub fn try_lock_unqueued(&self) -> Option<MutexGuard<'_, T>> {
        let mut inner = self.inner.lock();
        if inner.locked || !inner.waiters.is_empty() {
            return None;
        }
        inner.locked = true;
        Some(MutexGuard { mutex: self })
    }

    /// `true` if the lock is currently held by some task. Diagnostic
    /// only — the result is racy with respect to concurrent
    /// acquire/release on other CPUs.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.inner.lock().locked
    }

    /// Who has the lock, for state dumps: held or not, the waiter a release
    /// handed it to that has not yet run to claim it (it owns the lock
    /// meanwhile, so nothing else can take it), and how many wait. A lock
    /// held by a grantee that never runs looks free to every other
    /// diagnostic; this names it. Racy, like [`Self::is_locked`].
    pub fn held_state(&self) -> HeldState {
        let inner = self.inner.lock();
        HeldState {
            locked: inner.locked,
            granted_to: inner.granted.map(|WaiterId(id)| id),
            waiters: inner.waiters.len(),
        }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("Mutex")
            .field("locked", &inner.locked)
            .field("waiters", &inner.waiters.len())
            .finish_non_exhaustive()
    }
}

/// Where a waiter on this CPU last found a lock taken: the call site of
/// its `lock()`. A task that parks right after takes it
/// ([`take_wait_site`]) so the kernel can say what a blocked task waits on
/// — the hung-task question "which lock?". One pointer per CPU, written on
/// the slow path only.
static WAIT_SITE: [core::sync::atomic::AtomicPtr<core::panic::Location<'static>>;
    crate::percpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) }; crate::percpu::MAX_CPUS];

/// Record that a lock acquired at `site` is making this CPU's current
/// poll wait. Any lock type may report here.
pub fn note_wait_site(site: &'static core::panic::Location<'static>) {
    let cpu = crate::percpu::current_cpu();
    if let Some(slot) = WAIT_SITE.get(cpu) {
        slot.store(site as *const _ as *mut _, Ordering::Relaxed);
    }
}

/// Take what [`note_wait_site`] recorded on this CPU since the last take.
pub fn take_wait_site() -> Option<&'static core::panic::Location<'static>> {
    let cpu = crate::percpu::current_cpu();
    let raw = WAIT_SITE
        .get(cpu)?
        .swap(core::ptr::null_mut(), Ordering::Relaxed);
    // SAFETY: only `note_wait_site` stores here, from a `&'static Location`.
    (!raw.is_null()).then(|| unsafe { &*raw })
}

/// Future returned by [`Mutex::lock`].
pub struct LockFuture<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
    waiter_id: Option<WaiterId>,
    /// Where `lock()` was called, for [`note_wait_site`].
    site: &'static core::panic::Location<'static>,
}

impl<T: ?Sized> fmt::Debug for LockFuture<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockFuture")
            .field("registered", &self.waiter_id.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a, T: ?Sized> Future for LockFuture<'a, T> {
    type Output = MutexGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<MutexGuard<'a, T>> {
        let this = self.get_mut();
        let mut inner = this.mutex.inner.lock();

        // Fast path: free, take it. If we had a waiter slot it's
        // because we lost an earlier race — drop our entry (the
        // popper was about to wake us anyway, but we got there
        // first via direct poll).
        if !inner.locked {
            inner.locked = true;
            if let Some(id) = this.waiter_id.take() {
                inner.waiters.retain(|(wid, _)| *wid != id);
            }
            return Poll::Ready(MutexGuard { mutex: this.mutex });
        }

        // Handed to us by the last release: ours already.
        if this.waiter_id.is_some() && inner.granted == this.waiter_id {
            inner.granted = None;
            this.waiter_id = None;
            return Poll::Ready(MutexGuard { mutex: this.mutex });
        }

        // Locked. Either install our waker for the first time or
        // refresh it (the executor may re-poll us with a fresh
        // waker if the task was donated, migrated, etc.).
        match this.waiter_id {
            None => {
                let id = next_waiter_id();
                this.waiter_id = Some(id);
                inner.waiters.push_back((id, cx.waker().clone()));
            }
            Some(id) => {
                if let Some((_, w)) = inner.waiters.iter_mut().find(|(wid, _)| *wid == id) {
                    if !w.will_wake(cx.waker()) {
                        *w = cx.waker().clone();
                    }
                } else {
                    // Our slot was popped (a concurrent release woke
                    // us) but the lock was taken before we re-polled,
                    // by someone who never queued. Going to the back
                    // here let a waiter be passed over without bound:
                    // a volume-wide filesystem lock under a dozen busy
                    // threads left `msync`, `ftruncate`, `rename` and
                    // `fdatasync` waiting for minutes. As Linux
                    // (`__mutex_handoff`), take the front instead and
                    // have the next release hand the lock over.
                    inner.waiters.push_front((id, cx.waker().clone()));
                    inner.handoff = true;
                }
            }
        }
        note_wait_site(this.site);
        Poll::Pending
    }
}

impl<T: ?Sized> Drop for LockFuture<'_, T> {
    fn drop(&mut self) {
        // Cancelled before completion — clean our entry out so we
        // don't burn a wake on a dead future. If we were already
        // popped (about to be Ready) we have to wake the next
        // waiter ourselves: the popper wrote `locked = true` (no —
        // see below), or counted us as the new holder.
        //
        // Actually: a popper does NOT set locked. The release path
        // is `locked = false; pop; wake`. If we've been woken but
        // dropped before we could re-poll, the lock is already
        // free; the next poll of any other waiter (who got woken
        // by a separate release) will grab it. But if we were the
        // *only* waker the popper woke, our drop here means
        // nothing else will ever get woken — we have to chain.
        //
        // Simpler invariant: every Drop, if we have a waiter_id
        // that is no longer in the queue (= we were already
        // popped + woken), wake the front of the queue so the
        // chain continues.
        let Some(id) = self.waiter_id else { return };
        let mut inner = self.mutex.inner.lock();
        if inner.granted == Some(id) {
            // The lock was handed to us and never claimed: pass it on.
            inner.granted = None;
            if let Some(waker) = release_locked(&mut inner) {
                drop(inner);
                waker.wake();
            }
            return;
        }
        let pre = inner.waiters.len();
        inner.waiters.retain(|(wid, _)| *wid != id);
        let still_there = inner.waiters.len() != pre;
        if still_there {
            // We removed ourselves; nothing else needed.
            return;
        }
        // We were no longer in the queue → a release had popped +
        // woken us. The lock is currently free. Pop the next
        // waiter (if any) and wake them, since our wake is being
        // discarded.
        if !inner.locked {
            if let Some((_, w)) = inner.waiters.pop_front() {
                drop(inner);
                w.wake();
            }
        }
    }
}

/// RAII guard holding the lock. Releases on drop and wakes the
/// next waiter (if any).
pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

impl<T: ?Sized> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MutexGuard").finish_non_exhaustive()
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: holding the guard means no other reference exists.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the guard means no other reference exists.
        unsafe { &mut *self.mutex.data.get() }
    }
}

/// Release the lock with `inner` held: hand it to the front waiter if a
/// hand-off is due, else free it and wake the front waiter. Returns the
/// waker to call once `inner` is released.
fn release_locked(inner: &mut MutexInner) -> Option<Waker> {
    let next = inner.waiters.pop_front();
    match next {
        Some((id, waker)) if inner.handoff => {
            inner.handoff = false;
            inner.granted = Some(id);
            Some(waker)
        }
        Some((_, waker)) => {
            inner.locked = false;
            Some(waker)
        }
        None => {
            inner.handoff = false;
            inner.locked = false;
            None
        }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        let mut inner = self.mutex.inner.lock();
        let next = release_locked(&mut inner);
        drop(inner);
        if let Some(w) = next {
            w.wake();
        }
    }
}

// Kernel smoke tests live in lib/src/tests.rs. The optional optimistic
// admission rule also has a direct host test below.

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn optimistic_admission_defers_to_queued_waiters() {
        let mutex = Mutex::new(());
        let holder = mutex.try_lock().unwrap();
        let mut a = mutex.lock();
        let mut b = mutex.lock();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut a).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut b).poll(&mut cx).is_pending());
        drop(holder); // A is woken; B is still queued.
        assert!(mutex.try_lock_unqueued().is_none());
        let Poll::Ready(a_guard) = Pin::new(&mut a).poll(&mut cx) else {
            panic!("optimistic admission displaced the first waiter");
        };
        drop(a_guard);
        let Poll::Ready(b_guard) = Pin::new(&mut b).poll(&mut cx) else {
            panic!("the remaining queued waiter was stranded");
        };
        assert!(mutex.try_lock_unqueued().is_none());
        drop(b_guard);
        assert!(mutex.try_lock_unqueued().is_some());
    }

    #[test]
    fn a_waiter_passed_over_once_is_handed_the_lock() {
        let mutex = Mutex::new(());
        let holder = mutex.try_lock().unwrap();
        let mut a = mutex.lock();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut a).poll(&mut cx).is_pending());
        // A is woken; a newcomer gets in first.
        drop(holder);
        let barger = mutex.try_lock().expect("the lock was free");
        // A loses that race once ...
        assert!(Pin::new(&mut a).poll(&mut cx).is_pending());
        // ... and is handed the lock on the next release: no one else,
        // queued or not, can take it in between.
        drop(barger);
        assert!(mutex.try_lock().is_none());
        // The grant shows in the state dump until A runs to claim it.
        let held = mutex.held_state();
        assert!(held.locked && held.granted_to.is_some());
        let mut c = mutex.lock();
        assert!(Pin::new(&mut c).poll(&mut cx).is_pending());
        let Poll::Ready(a_guard) = Pin::new(&mut a).poll(&mut cx) else {
            panic!("the passed-over waiter was not handed the lock");
        };
        drop(a_guard);
        let Poll::Ready(c_guard) = Pin::new(&mut c).poll(&mut cx) else {
            panic!("the next waiter was stranded");
        };
        drop(c_guard);
        assert!(mutex.try_lock().is_some());
    }

    #[test]
    fn a_handed_lock_that_is_never_claimed_passes_on() {
        let mutex = Mutex::new(());
        let holder = mutex.try_lock().unwrap();
        let mut a = mutex.lock();
        let mut b = mutex.lock();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut a).poll(&mut cx).is_pending());
        assert!(Pin::new(&mut b).poll(&mut cx).is_pending());
        drop(holder);
        let barger = mutex.try_lock().expect("the lock was free");
        assert!(Pin::new(&mut a).poll(&mut cx).is_pending());
        drop(barger); // handed to A
        drop(a); // A gives up without claiming it
        let Poll::Ready(b_guard) = Pin::new(&mut b).poll(&mut cx) else {
            panic!("a lock handed to a cancelled waiter was lost");
        };
        drop(b_guard);
        assert!(mutex.try_lock().is_some());
    }
}
