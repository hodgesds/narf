//! Locks for module code.
//!
//! [`SpinLock`] guards short critical sections shared between the module's
//! concurrent upcalls (poller, IRQ pumps, probe) on different CPUs. Its guard
//! is `!Send`, which keeps the kernel's compile-time rule: a future that holds
//! a spin-lock guard across `.await` is itself `!Send`, and
//! [`crate::exec::Executor::spawn`] requires `Send`.
//!
//! [`Mutex`] is the async lock that *may* be held across `.await`. Waiters
//! park their waker; the release wakes them.
//!
//! Neither masks interrupts: module code never runs in hard-IRQ context (see
//! the crate docs), so an upcall can only contend with another CPU.

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt;
use core::future::Future;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

/// A test-and-test-and-set spin lock.
pub struct SpinLock<T: ?Sized> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: the lock serialises all access to `data`, so sharing the lock
// across threads only ever moves `T` between them one holder at a time.
unsafe impl<T: ?Sized + Send> Send for SpinLock<T> {}
// SAFETY: as above.
unsafe impl<T: ?Sized + Send> Sync for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// An unlocked lock around `value`.
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    /// Consume the lock, returning the value.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> SpinLock<T> {
    /// Spin until the lock is acquired.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        loop {
            if let Some(guard) = self.try_lock() {
                return guard;
            }
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    /// Acquire the lock if it is free.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }

    /// Whether some holder has the lock right now (a racy hint).
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }

    /// Mutable access through an exclusive borrow; no locking needed.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLock<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_lock() {
            Some(guard) => f.debug_struct("SpinLock").field("data", &&*guard).finish(),
            None => f.write_str("SpinLock { <locked> }"),
        }
    }
}

impl<T: Default> Default for SpinLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// Holds a [`SpinLock`]; releases it on drop.
pub struct SpinLockGuard<'a, T: ?Sized> {
    lock: &'a SpinLock<T>,
}

impl<T: ?Sized> !Send for SpinLockGuard<'_, T> {}
// SAFETY: a shared guard only hands out `&T`, which is sound to share when
// `T: Sync` (the explicit impl replaces the auto impl, which would have
// required only `T: Send`).
unsafe impl<T: ?Sized + Sync> Sync for SpinLockGuard<'_, T> {}

impl<T: ?Sized> Deref for SpinLockGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard is the unique holder of the lock.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard is the unique holder of the lock.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for SpinLockGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

/// An async mutex: its guard may be held across `.await`.
pub struct Mutex<T: ?Sized> {
    locked: AtomicBool,
    waiters: SpinLock<Vec<Waker>>,
    data: UnsafeCell<T>,
}

// SAFETY: the `locked` flag serialises all access to `data`.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}
// SAFETY: as above.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

impl<T> Mutex<T> {
    /// An unlocked mutex around `value`.
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            waiters: SpinLock::new(Vec::new()),
            data: UnsafeCell::new(value),
        }
    }

    /// Consume the mutex, returning the value.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquire the mutex, waiting asynchronously while another task holds it.
    pub fn lock(&self) -> LockFuture<'_, T> {
        LockFuture { mutex: self }
    }

    /// Acquire the mutex if it is free.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(MutexGuard { mutex: self })
        } else {
            None
        }
    }

    /// Mutable access through an exclusive borrow; no locking needed.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
        let waiters = core::mem::take(&mut *self.waiters.lock());
        for waker in waiters {
            waker.wake();
        }
    }
}

impl<T: ?Sized> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mutex")
            .field("locked", &self.locked.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// Future returned by [`Mutex::lock`].
#[must_use = "futures do nothing unless polled"]
pub struct LockFuture<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

impl<T: ?Sized> fmt::Debug for LockFuture<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LockFuture")
    }
}

impl<'a, T: ?Sized> Future for LockFuture<'a, T> {
    type Output = MutexGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<MutexGuard<'a, T>> {
        if let Some(guard) = self.mutex.try_lock() {
            return Poll::Ready(guard);
        }
        {
            let mut waiters = self.mutex.waiters.lock();
            if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                waiters.push(cx.waker().clone());
            }
        }
        // The holder may have released between the first attempt and parking
        // the waker, taking an empty waiter list with it; try once more so
        // that release is not lost.
        match self.mutex.try_lock() {
            Some(guard) => Poll::Ready(guard),
            None => Poll::Pending,
        }
    }
}

/// Holds a [`Mutex`]; releases it (and wakes waiters) on drop.
pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

// SAFETY: a shared guard only hands out `&T`; see `SpinLockGuard`.
unsafe impl<T: ?Sized + Sync> Sync for MutexGuard<'_, T> {}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard is the unique holder of the mutex.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard is the unique holder of the mutex.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.unlock();
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
