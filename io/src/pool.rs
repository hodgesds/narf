//! Recycling DMA-buffer pool.
//!
//! At 10/40/100G a NIC burns through millions of RX/TX buffers a second;
//! calling the page allocator (and zero-filling a page) per packet is a
//! throughput ceiling long before the wire is. A `DmaPool` is one queue's
//! bounded free-list of same-sized coherent buffers.  The driver prepares and
//! pre-fills it while bringing the queue up, then its packet path uses only
//! [`DmaPool::try_acquire`] / [`DmaPool::release`].  Those operations take one
//! short queue-local lock and never allocate.  Empty pools apply backpressure
//! (drop or defer the packet); they do *not* fall back to the buddy allocator.
//!
//! [`DmaPool::acquire`] remains an explicit control/refill API for setup and
//! recovery. It may allocate.  Keeping the two paths distinct makes an
//! accidental allocator call in an RX/TX completion path auditable.
//!
//! This is the shared primitive behind P-F "zero-copy + buffer recycling":
//! virtio-net and the Ethernet drivers all recycle through one implementation
//! instead of each hand-rolling a `Vec<DmaBuffer>` free-list.
//!
//! The device overwrites an RX buffer completely on receive and a TX buffer is
//! written before submit, so a recycled (un-zeroed) buffer is always safe —
//! the pool never re-zeroes, which is the whole point.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{alloc_coherent, DmaBuffer};

/// Snapshot of a queue pool's hot-path behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DmaPoolStats {
    /// Buffers acquired from the recycler without allocating.
    pub cache_hits: u64,
    /// Hot-path acquisitions that found no recycled buffer.
    pub cache_misses: u64,
    /// Buffers not retained because the bounded recycler was full or unprepared.
    pub recycle_drops: u64,
}

/// A bounded, queue-local free-list of recycled coherent DMA buffers of one
/// fixed size. Create one per hardware RX/TX queue; sharing one pool among
/// queue pairs serializes their completion paths and does not scale.
#[derive(Debug)]
pub struct DmaPool {
    free: IrqSafeSpinLock<Vec<DmaBuffer>>,
    buf_len: usize,
    domain: DomainId,
    cap: usize,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    recycle_drops: AtomicU64,
}

impl DmaPool {
    /// A pool of `buf_len`-byte buffers in `domain`, holding at most `cap`
    /// recycled buffers before `release` starts freeing. `const` so a driver
    /// can hold one in a `static` and fill it lazily on first `acquire`.
    pub const fn new(buf_len: usize, domain: DomainId, cap: usize) -> Self {
        Self {
            free: IrqSafeSpinLock::new(Vec::new()),
            buf_len,
            domain,
            cap,
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            recycle_drops: AtomicU64::new(0),
        }
    }

    /// Buffer size this pool hands out.
    pub fn buf_len(&self) -> usize {
        self.buf_len
    }

    /// Number of recycled buffers currently parked in the free-list.
    pub fn available(&self) -> usize {
        self.free.lock().len()
    }

    /// Reserve the recycler's metadata capacity without holding its queue lock
    /// across allocation. Call at queue setup, before interrupts or NAPI-like
    /// polling can start. A pool that was not prepared intentionally refuses to
    /// retain releases: growing the `Vec` from an IRQ completion path would put
    /// the general allocator back on the hot path.
    pub fn prepare(&self) -> bool {
        if self.free.lock().capacity() >= self.cap {
            return true;
        }

        let mut replacement = Vec::new();
        if replacement.try_reserve_exact(self.cap).is_err() {
            return false;
        }

        let mut free = self.free.lock();
        if free.capacity() >= self.cap {
            return true;
        }
        debug_assert!(free.len() <= self.cap);
        replacement.extend(free.drain(..));
        *free = replacement;
        true
    }

    /// Hot-path acquire. Returns only a buffer that has already been
    /// recycled; it never allocates or zero-fills. Queue code treats `None` as
    /// backpressure and lets its refill/recovery worker call [`Self::acquire`]
    /// later.
    pub fn try_acquire(&self) -> Option<DmaBuffer> {
        let buf = self.free.lock().pop();
        if buf.is_some() {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
        buf
    }

    /// Batch hot-path acquire, taking the pool lock once for an entire RX/TX
    /// completion batch. `out` must contain empty slots; returns how many were
    /// filled. No allocation or allocator fallback occurs.
    pub fn try_acquire_batch(&self, out: &mut [Option<DmaBuffer>]) -> usize {
        let mut free = self.free.lock();
        let mut acquired = 0;
        for slot in out.iter_mut() {
            debug_assert!(slot.is_none(), "batch output slot must be empty");
            let Some(buf) = free.pop() else {
                break;
            };
            *slot = Some(buf);
            acquired += 1;
        }
        self.cache_hits
            .fetch_add(acquired as u64, Ordering::Relaxed);
        self.cache_misses
            .fetch_add((out.len() - acquired) as u64, Ordering::Relaxed);
        acquired
    }

    /// Control/refill acquire: a recycled buffer if available, otherwise a
    /// fresh coherent allocation. Do not call from packet completion or IRQ
    /// paths; use [`Self::try_acquire`] there. `None` only when the allocator
    /// is out of memory.
    pub fn acquire(&self) -> Option<DmaBuffer> {
        self.try_acquire()
            .or_else(|| alloc_coherent(self.buf_len, self.domain).ok())
    }

    /// Return a fully-consumed buffer for hot-path reuse, or drop it (freeing)
    /// after the queue lock has been released when the recycler is full or was
    /// not prepared. A buffer whose capacity no longer matches the pool's
    /// `buf_len` is also dropped, so a later acquire can never hand out a
    /// wrong-sized buffer. This function never grows the free-list.
    pub fn release(&self, buf: DmaBuffer) {
        let mut buf = Some(buf);
        if buf.as_ref().is_some_and(|buf| buf.len() < self.buf_len) {
            self.recycle_drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let retained = {
            let mut free = self.free.lock();
            if free.len() < self.cap && free.len() < free.capacity() {
                free.push(buf.take().expect("buffer remains owned"));
                true
            } else {
                false
            }
        };
        if !retained {
            self.recycle_drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Batch recycle under one queue-local lock. Retained entries are replaced
    /// with `None`; entries left as `Some` were not accepted and drop when the
    /// caller releases the array, after this method has dropped the lock. This
    /// makes overflow freeing explicitly outside the completion critical
    /// section.
    pub fn release_batch(&self, bufs: &mut [Option<DmaBuffer>]) -> usize {
        let mut retained = 0;
        {
            let mut free = self.free.lock();
            for slot in bufs.iter_mut() {
                let Some(buf) = slot.as_ref() else {
                    continue;
                };
                if buf.len() < self.buf_len
                    || free.len() >= self.cap
                    || free.len() >= free.capacity()
                {
                    continue;
                }
                // `take` moves ownership into the already-reserved Vec.
                free.push(slot.take().expect("checked Some"));
                retained += 1;
            }
        }
        self.recycle_drops.fetch_add(
            (bufs.iter().filter(|buf| buf.is_some()).count()) as u64,
            Ordering::Relaxed,
        );
        retained
    }

    /// Queue-pool counters. Reading them is diagnostic only and not part of
    /// the packet path.
    pub fn stats(&self) -> DmaPoolStats {
        DmaPoolStats {
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            recycle_drops: self.recycle_drops.load(Ordering::Relaxed),
        }
    }

    /// Pre-allocate up to `n` buffers into the free-list so the first burst of
    /// traffic does no allocation on the hot path. Allocation happens outside
    /// the queue lock; returns how many were added (fewer than `n` if metadata
    /// or buffer allocation ran short, or `cap` was reached).
    pub fn prefill(&self, n: usize) -> usize {
        if !self.prepare() {
            return 0;
        }
        let mut added = 0;
        while added < n {
            if self.available() >= self.cap {
                break;
            }
            match alloc_coherent(self.buf_len, self.domain) {
                Ok(b) => {
                    let mut b = Some(b);
                    let retained = {
                        let mut free = self.free.lock();
                        if free.len() < self.cap && free.len() < free.capacity() {
                            free.push(b.take().expect("fresh buffer remains owned"));
                            true
                        } else {
                            false
                        }
                    };
                    if retained {
                        added += 1;
                    } else {
                        self.recycle_drops.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        added
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod pool_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_dma_pool_recycle() -> TestResult {
        let pool = DmaPool::new(2048, DomainId::DRIVER_0, 4);
        if pool.available() != 0 {
            return TestResult::Fail("fresh pool should be empty");
        }
        // The hot path never allocates: an empty pool asks its caller to apply
        // backpressure instead of falling back to the buddy allocator.
        if pool.try_acquire().is_some() || pool.stats().cache_misses != 1 {
            return TestResult::Fail("empty hot acquire allocated or missed no stats");
        }
        if pool.prefill(4) != 4 || pool.available() != 4 {
            return TestResult::Fail("prefill did not prepare the queue pool");
        }
        let a = match pool.try_acquire() {
            Some(b) => b,
            None => return TestResult::Fail("hot acquire missed a prefilled pool"),
        };
        if a.len() < 2048 {
            return TestResult::Fail("acquired buffer smaller than buf_len");
        }
        // release parks it; the next acquire returns that same storage (no new
        // allocation) — proven by the free-list depth going 0→1→0.
        pool.release(a);
        if pool.available() != 1 {
            return TestResult::Fail("release did not park the buffer");
        }
        let _b = pool.try_acquire();
        if pool.available() != 0 {
            return TestResult::Fail("acquire did not reuse the parked buffer");
        }

        // The free-list is bounded by cap: releasing more than cap frees the
        // overflow rather than growing without bound.
        let pool = DmaPool::new(2048, DomainId::DRIVER_0, 2);
        if pool.prefill(2) != 2 {
            return TestResult::Fail("could not prefill two buffers");
        }
        let a = pool.try_acquire();
        let b = pool.try_acquire();
        let overflow = pool.acquire(); // explicit control-path allocation
        if a.is_none() || b.is_none() || overflow.is_none() {
            return TestResult::Fail("could not acquire pool overflow fixture");
        }
        pool.release(a.unwrap());
        pool.release(b.unwrap());
        pool.release(overflow.unwrap());
        if pool.available() != 2 {
            return TestResult::Fail("free-list exceeded cap");
        }
        if pool.stats().recycle_drops == 0 {
            return TestResult::Fail("full pool retained overflow buffer");
        }
        TestResult::Pass
    }
    kernel_test_in!("io/pool", smoke_dma_pool_recycle);

    fn smoke_dma_pool_prefill() -> TestResult {
        let pool = DmaPool::new(4096, DomainId::DRIVER_0, 8);
        let added = pool.prefill(5);
        if added != 5 || pool.available() != 5 {
            return TestResult::Fail("prefill did not warm the pool");
        }
        // prefill never exceeds cap.
        let more = pool.prefill(10);
        if pool.available() != 8 || more != 3 {
            return TestResult::Fail("prefill exceeded cap");
        }
        TestResult::Pass
    }
    kernel_test_in!("io/pool", smoke_dma_pool_prefill);

    fn smoke_dma_pool_batch_hot_path() -> TestResult {
        let pool = DmaPool::new(2048, DomainId::DRIVER_0, 4);
        if pool.prefill(4) != 4 {
            return TestResult::Fail("could not prefill batch fixture");
        }
        let mut batch: [Option<DmaBuffer>; 3] = [const { None }; 3];
        if pool.try_acquire_batch(&mut batch) != 3 || pool.available() != 1 {
            return TestResult::Fail("batch acquire did not take three cached buffers");
        }
        if pool.release_batch(&mut batch) != 3
            || batch.iter().any(Option::is_some)
            || pool.available() != 4
        {
            return TestResult::Fail("batch release did not recycle all buffers");
        }
        TestResult::Pass
    }
    kernel_test_in!("io/pool", smoke_dma_pool_batch_hot_path);
}
