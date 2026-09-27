//! Sleepable ownership for payload work; lockless snapshots for poll/close.
use crate::pipe_buffer::PipeBufs;
use core::{
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
use narf_lib::mutex::{Mutex, MutexGuard};

const FULL: u64 = 1 << 63;

#[derive(Debug)]
pub struct Queue {
    data: Mutex<PipeBufs>,
    state: AtomicU64,
    capacity: AtomicUsize,
}

impl Queue {
    pub fn new(data: PipeBufs) -> Self {
        let capacity = data.capacity();
        Self {
            data: Mutex::new(data),
            state: AtomicU64::new(0),
            capacity: AtomicUsize::new(capacity),
        }
    }
    pub async fn lock_async(&self) -> Guard<'_> {
        Guard {
            queue: self,
            data: self.data.lock().await,
        }
    }
    pub fn try_lock(&self) -> Option<Guard<'_>> {
        Some(Guard {
            queue: self,
            data: self.data.try_lock()?,
        })
    }
    pub fn snapshot(&self) -> (usize, bool) {
        let state = self.state.load(Ordering::Acquire);
        ((state & !FULL) as usize, state & FULL != 0)
    }
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Acquire)
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
    }
}
