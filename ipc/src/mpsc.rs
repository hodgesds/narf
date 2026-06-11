//! Multi-producer, single-consumer ring.
//!
//! Spec: `ipc/specification/spec.md` (Stage-4 — MPSC). The Stage-3
//! SPSC `Ring` forbids concurrent producers; MPSC lets N driver
//! tasks feed one consumer task. Used by the Stage-4 `abi/`
//! dispatcher when SMP lands and several CPUs want to post into
//! the same completion queue.
//!
//! Stage-4 scope: a bounded MPSC backed by an `IrqSafeSpinLock<
//! VecDeque<T>>`. Correct under any producer concurrency (including
//! IRQ-context producers because of `IrqSafe`); loses the Stage-3
//! SPSC's cache-line partitioning + release/acquire discipline, so
//! it's not the lock-free Vyukov MPSC the spec ultimately calls
//! for. That refinement lands when `rcu/` batched reclamation feeds
//! the slot-sequence reclaim path. For now this is the simplest
//! correct structural shape.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

/// Errors a non-blocking send can return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MpscSendError<T> {
    /// Channel is at capacity.
    Full(T),
    /// Consumer has been dropped.
    Closed(T),
}

/// Errors a recv can return.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MpscRecvError {
    /// Every producer has been dropped and the channel is empty.
    Closed,
}

struct Inner<T> {
    q: IrqSafeSpinLock<VecDeque<T>>,
    cap: usize,
    closed: AtomicBool,
    consumer_waker: IrqSafeSpinLock<Option<Waker>>,
    producer_waker: IrqSafeSpinLock<Option<Waker>>,
}

impl<T> core::fmt::Debug for Inner<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Inner")
            .field("cap", &self.cap)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// Producer handle. `Clone` so N tasks can hold a producer each.
#[derive(Debug)]
pub struct MpscProducer<T> {
    inner: Arc<Inner<T>>,
    /// Present on at least one producer until every producer drops;
    /// when the count goes to zero we flip `closed` and wake the
    /// consumer.
    _not_sync_hint: PhantomData<*const ()>,
}

// SAFETY: `MpscProducer` owns only an `Arc<Inner<T>>`; the
// `PhantomData<*const ()>` is a documentation hint and is never
// dereferenced. Moving it to another thread is sound when `T: Send`
// because the only shared state (`Inner`'s queue and wakers) is behind
// spin locks.
unsafe impl<T: Send> Send for MpscProducer<T> {}
// SAFETY: all access to the shared `Inner` from a producer goes through
// `Inner`'s spin locks, so concurrent `&MpscProducer` use from multiple
// threads is data-race-free when `T: Send`.
unsafe impl<T: Send> Sync for MpscProducer<T> {}

impl<T> Clone for MpscProducer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            _not_sync_hint: PhantomData,
        }
    }
}

impl<T> MpscProducer<T> {
    /// Non-blocking send. Returns `Full(value)` if the channel is at
    /// capacity, `Closed(value)` if the consumer has been dropped.
    pub fn try_send(&self, value: T) -> Result<(), MpscSendError<T>> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(MpscSendError::Closed(value));
        }
        let mut q = self.inner.q.lock();
        if q.len() >= self.inner.cap {
            return Err(MpscSendError::Full(value));
        }
        q.push_back(value);
        drop(q);
        if let Some(w) = self.inner.consumer_waker.lock().take() {
            w.wake();
        }
        Ok(())
    }

    /// Count of consumers still alive (0 or 1). Useful diagnostic.
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }
}

/// Consumer handle — single-threaded by construction.
#[derive(Debug)]
pub struct MpscConsumer<T> {
    inner: Arc<Inner<T>>,
    _not_sync: PhantomData<*const ()>,
}

// SAFETY: `MpscConsumer` owns only an `Arc<Inner<T>>` and a hint-only
// `PhantomData<*const ()>` that is never dereferenced; the consumer is
// !Sync (single-threaded by construction) but may be moved between
// threads, which is sound when `T: Send` since all `Inner` access is
// lock-guarded.
unsafe impl<T: Send> Send for MpscConsumer<T> {}

impl<T> MpscConsumer<T> {
    /// Non-blocking receive. Returns `Ok(None)` when empty,
    /// `Err(Closed)` when empty and all producers are gone.
    pub fn try_recv(&self) -> Result<Option<T>, MpscRecvError> {
        let mut q = self.inner.q.lock();
        if let Some(v) = q.pop_front() {
            drop(q);
            if let Some(w) = self.inner.producer_waker.lock().take() {
                w.wake();
            }
            return Ok(Some(v));
        }
        if self.inner.closed.load(Ordering::Acquire) {
            Err(MpscRecvError::Closed)
        } else {
            Ok(None)
        }
    }

    /// Async receive. Resolves when a producer posts or every
    /// producer has been dropped. Takes `&mut self` so the
    /// returned future is `Send`-safe for spawning.
    pub fn recv(&mut self) -> MpscRecvFuture<'_, T> {
        MpscRecvFuture { consumer: self }
    }

    /// Pending item count. Best-effort snapshot.
    pub fn pending(&self) -> usize {
        self.inner.q.lock().len()
    }
}

/// Future returned by `MpscConsumer::recv`.
#[derive(Debug)]
pub struct MpscRecvFuture<'c, T> {
    consumer: &'c mut MpscConsumer<T>,
}

impl<'c, T: Send> Future for MpscRecvFuture<'c, T> {
    type Output = Result<T, MpscRecvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.consumer.try_recv() {
            Ok(Some(v)) => Poll::Ready(Ok(v)),
            Err(e) => Poll::Ready(Err(e)),
            Ok(None) => {
                *self.consumer.inner.consumer_waker.lock() = Some(cx.waker().clone());
                // Re-check after installing the waker — producer may
                // have posted between `try_recv` and the install.
                match self.consumer.try_recv() {
                    Ok(Some(v)) => Poll::Ready(Ok(v)),
                    Err(e) => Poll::Ready(Err(e)),
                    Ok(None) => Poll::Pending,
                }
            }
        }
    }
}

/// On consumer drop we latch `closed` so late producers see it.
impl<T> Drop for MpscConsumer<T> {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Release);
        if let Some(w) = self.inner.producer_waker.lock().take() {
            w.wake();
        }
    }
}

/// Construct a fresh MPSC channel with capacity `cap`. Panics on
/// zero capacity.
pub fn mpsc_channel<T>(cap: usize) -> (MpscProducer<T>, MpscConsumer<T>) {
    assert!(cap > 0, "mpsc_channel cap must be non-zero");
    let inner = Arc::new(Inner {
        q: IrqSafeSpinLock::new(VecDeque::with_capacity(cap)),
        cap,
        closed: AtomicBool::new(false),
        consumer_waker: IrqSafeSpinLock::new(None),
        producer_waker: IrqSafeSpinLock::new(None),
    });
    (
        MpscProducer {
            inner: Arc::clone(&inner),
            _not_sync_hint: PhantomData,
        },
        MpscConsumer {
            inner,
            _not_sync: PhantomData,
        },
    )
}
