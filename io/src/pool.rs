//! Recycling DMA-buffer pool.
//!
//! At 10/40/100G a NIC burns through millions of RX/TX buffers a second;
//! calling the page allocator (and zero-filling a page) per packet is a
//! throughput ceiling long before the wire is. A `DmaPool` keeps a bounded
//! free-list of same-sized coherent buffers: `acquire` reuses a freed buffer
//! (or allocates one when the list is empty), and `release` returns a
//! fully-consumed buffer to the list (or drops it, freeing, when the list is
//! already full). The RX path refills from it; the TX path reclaims into it on
//! completion — so the steady state does no per-packet allocation.
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

use narf_lib::id::DomainId;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{alloc_coherent, DmaBuffer};

/// A bounded free-list of recycled coherent DMA buffers of one fixed size.
#[derive(Debug)]
pub struct DmaPool {
    free: IrqSafeSpinLock<Vec<DmaBuffer>>,
    buf_len: usize,
    domain: DomainId,
    cap: usize,
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

    /// Take a buffer: a recycled one if the free-list has any, else a fresh
    /// coherent allocation. `None` only when the allocator is out of memory.
    pub fn acquire(&self) -> Option<DmaBuffer> {
        if let Some(b) = self.free.lock().pop() {
            return Some(b);
        }
        alloc_coherent(self.buf_len, self.domain).ok()
    }

    /// Return a fully-consumed buffer for reuse, or drop it (freeing) when the
    /// free-list is already at `cap`. A buffer whose capacity no longer matches
    /// the pool's `buf_len` (a misuse) is dropped rather than recycled, so a
    /// later `acquire` can never hand out a wrong-sized buffer.
    pub fn release(&self, buf: DmaBuffer) {
        if buf.len() < self.buf_len {
            return;
        }
        let mut free = self.free.lock();
        if free.len() < self.cap {
            free.push(buf);
        }
    }

    /// Pre-allocate up to `n` buffers into the free-list so the first burst of
    /// traffic does no allocation on the hot path. Returns how many were added
    /// (fewer than `n` if the allocator ran short or `cap` was reached).
    pub fn prefill(&self, n: usize) -> usize {
        let mut added = 0;
        let mut free = self.free.lock();
        while added < n && free.len() < self.cap {
            match alloc_coherent(self.buf_len, self.domain) {
                Ok(b) => {
                    free.push(b);
                    added += 1;
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
        // acquire on an empty pool allocates; the buffer is at least buf_len.
        let a = match pool.acquire() {
            Some(b) => b,
            None => return TestResult::Fail("acquire failed on empty pool"),
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
        let _b = pool.acquire();
        if pool.available() != 0 {
            return TestResult::Fail("acquire did not reuse the parked buffer");
        }

        // The free-list is bounded by cap: releasing more than cap frees the
        // overflow rather than growing without bound.
        let pool = DmaPool::new(2048, DomainId::DRIVER_0, 2);
        let bufs: Vec<_> = (0..4).filter_map(|_| pool.acquire()).collect();
        if bufs.len() != 4 {
            return TestResult::Fail("could not acquire four buffers");
        }
        for b in bufs {
            pool.release(b);
        }
        if pool.available() != 2 {
            return TestResult::Fail("free-list exceeded cap");
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
}
