//! Sleepable ownership for payload work; lockless snapshots for poll/close.
use crate::pipe_buffer::PipeBufs;
use core::{
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};
use narf_lib::mutex::{Mutex, MutexGuard};

const FULL: u64 = 1 << 63;

#[derive(Debug)]
pub struct Queue {
    data: Mutex<PipeBufs>,
    state: AtomicU64,
    capacity: AtomicUsize,
    // Advisory only: readers can wait briefly without repeatedly taking the
    // mutex's internal waiter lock. Ownership still comes only from data.
    busy: AtomicBool,
    // At most one optional spinner per pipe. Other contenders park normally.
    spinner: AtomicBool,
}

impl Queue {
    pub fn new(data: PipeBufs) -> Self {
        let capacity = data.capacity();
        Self {
            data: Mutex::new(data),
            state: AtomicU64::new(0),
            capacity: AtomicUsize::new(capacity),
            busy: AtomicBool::new(false),
            spinner: AtomicBool::new(false),
        }
    }
    pub async fn lock_async(&self) -> Guard<'_> {
        let data = self.data.lock().await;
        self.guard(data)
    }
    pub fn try_lock(&self) -> Option<Guard<'_>> {
        Some(self.guard(self.data.try_lock()?))
    }

    /// A bounded optimistic wait for short payload operations. At most one
    /// contender spins, for at most 32 pauses, and it defers to queued mutex
    /// waiters. Preempted/faulting owners cannot create an unbounded spin.
    /// The busy hint never proves ownership: only the mutex grants the guard.
    pub fn try_lock_optimistic(&self) -> Option<Guard<'_>> {
        self.spinner
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        let _reservation = SpinReservation(&self.spinner);
        for _ in 0..32 {
            core::hint::spin_loop();
            if !self.busy.load(Ordering::Relaxed) {
                // One authoritative retry. On either a new owner or queued
                // sleepers, leave the spin path and use the normal mutex path.
                return Some(self.guard(self.data.try_lock_unqueued()?));
            }
        }
        None
    }

    fn guard<'a>(&'a self, data: MutexGuard<'a, PipeBufs>) -> Guard<'a> {
        self.busy.store(true, Ordering::Relaxed);
        Guard { queue: self, data }
    }
    pub fn snapshot(&self) -> (usize, bool) {
        let state = self.state.load(Ordering::Acquire);
        ((state & !FULL) as usize, state & FULL != 0)
    }
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
    }
}

struct SpinReservation<'a>(&'a AtomicBool);

impl Drop for SpinReservation<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub struct Guard<'a> {
    queue: &'a Queue,
    data: MutexGuard<'a, PipeBufs>,
}
impl core::fmt::Debug for Guard<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("PipeQueueGuard").field(&*self.data).finish()
    }
}
impl Deref for Guard<'_> {
    type Target = PipeBufs;
    fn deref(&self) -> &PipeBufs {
        &self.data
    }
}
impl DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut PipeBufs {
        &mut self.data
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        // Publish before releasing ownership. Poll and final fd destruction
        // never wait for the payload mutex (fd destruction may hold a table
        // spinlock). The mutator publishes readiness after dropping this guard.
        self.queue.state.store(
            self.data.len() as u64 | if self.data.is_full() { FULL } else { 0 },
            Ordering::Release,
        );
        self.queue
            .capacity
            .store(self.data.capacity(), Ordering::Release);
        // Clear before the mutex guard releases ownership. A successor cannot
        // set its hint until that release, so this owner cannot clear its hint.
        self.queue.busy.store(false, Ordering::Relaxed);
    }
}

mod tests {
    use super::*;
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pipe_optimistic_wait_defers_and_releases_reservation() -> TestResult {
        let queue = Queue::new(PipeBufs::new());
        let holder = queue.try_lock().unwrap();
        if queue.try_lock_optimistic().is_some() {
            return TestResult::Fail("optimistic wait acquired a held payload mutex");
        }
        let mut a = pin!(queue.lock_async());
        let mut b = pin!(queue.lock_async());
        let mut cx = Context::from_waker(Waker::noop());
        if a.as_mut().poll(&mut cx).is_ready() || b.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("contended pipe waiters unexpectedly acquired ownership");
        }
        drop(holder);
        // A was selected by release; B is still queued. An optimistic
        // contender must defer and release its optional spin reservation.
        if queue.try_lock_optimistic().is_some() {
            return TestResult::Fail("optimistic pipe wait bypassed a queued sleeper");
        }
        let Poll::Ready(a_guard) = a.as_mut().poll(&mut cx) else {
            return TestResult::Fail("optimistic wait displaced the selected pipe waiter");
        };
        drop(a_guard);
        let Poll::Ready(b_guard) = b.as_mut().poll(&mut cx) else {
            return TestResult::Fail("optimistic wait stranded the remaining pipe waiter");
        };
        drop(b_guard);
        if queue.try_lock_optimistic().is_none() {
            return TestResult::Fail("a failed optimistic wait retained its spin reservation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "filesystem/pipe",
        smoke_pipe_optimistic_wait_defers_and_releases_reservation
    );
}
