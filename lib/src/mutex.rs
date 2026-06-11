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
}

// SAFETY: `Mutex<T>` provides exclusive access to `T` through the
// guard, the same contract as `std::sync::Mutex`. `T: Send` is
// sufficient to share the mutex across tasks.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
// SAFETY: exclusive access is serialized by the lock; `T: Send` makes sharing the guarded value across tasks sound.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T) -> Self {
        Self {
            inner: IrqSafeSpinLock::new(MutexInner {
                locked: false,
                waiters: VecDeque::new(),
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
    pub fn lock(&self) -> LockFuture<'_, T> {
        LockFuture {
            mutex: self,
            waiter_id: None,
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

    /// `true` if the lock is currently held by some task. Diagnostic
    /// only — the result is racy with respect to concurrent
    /// acquire/release on other CPUs.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.inner.lock().locked
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

/// Future returned by [`Mutex::lock`].
pub struct LockFuture<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
    waiter_id: Option<WaiterId>,
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
                    // Our slot was popped (a concurrent release
                    // woke us) but the lock got stolen before we
                    // re-polled. Re-register at the back.
                    inner.waiters.push_back((id, cx.waker().clone()));
                }
            }
        }
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

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        let mut inner = self.mutex.inner.lock();
        inner.locked = false;
        let next = inner.waiters.pop_front();
        drop(inner);
        if let Some((_, w)) = next {
            w.wake();
        }
    }
}

// Smoke tests live in `lib/src/tests.rs` under the kernel-test
// harness — host `cargo test` can't link against narf-arch hooks
// the rest of the crate pulls in.
