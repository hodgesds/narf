//! Pure-FIFO I/O scheduler.
//!
//! `NoopScheduler` is the simplest possible `IoScheduler` impl: one
//! `VecDeque`, no read/write lane split, no deadline promotion, no
//! starvation avoidance. Useful as:
//!
//! - The reference "policy that does nothing" for pluggability
//!   smokes (the install path is what's under test, not the
//!   ordering).
//! - A baseline for workloads where the device itself reorders
//!   (NVMe namespaces with internal SLC caching, virtio-blk on a
//!   host that already runs its own scheduler).
//!
//! `cancel(req_id)` walks the queue linearly looking for an entry
//! whose tag matches. The queue is expected to stay short under
//! noop dispatch (the device drains on every `pick_next`), so the
//! O(n) walk is acceptable for the intended use.

use alloc::boxed::Box;
use alloc::collections::VecDeque;

use narf_lib::sync::IrqSafeSpinLock;

use crate::io_scheduler::IoScheduler;
use crate::BlockRequest;

/// One entry on the FIFO queue. The scheduler stamps a monotonic
/// tag on enqueue so `cancel` and the caller can correlate requests
/// across dispatch.
#[derive(Debug)]
struct Entry {
    tag: u64,
    req: BlockRequest,
}

/// FIFO scheduler. Behaviour:
///
/// - `enqueue` pushes to the tail and returns the next tag.
/// - `pick_next` pops from the head.
/// - `cancel` linearly searches for `tag` and removes the matching
///   entry if still queued.
#[derive(Debug)]
pub struct NoopScheduler {
    inner: IrqSafeSpinLock<Inner>,
}

#[derive(Debug)]
struct Inner {
    queue: VecDeque<Entry>,
    next_tag: u64,
}

impl NoopScheduler {
    pub const fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(Inner {
                queue: VecDeque::new(),
                next_tag: 1,
            }),
        }
    }

    /// Boxed convenience for `install_io_scheduler` callers that
    /// want a `Box<dyn IoScheduler>` directly.
    pub fn boxed() -> Box<dyn IoScheduler> {
        Box::new(Self::new())
    }

    /// Total pending requests. Convenience for smokes — not part of
    /// the `IoScheduler` trait.
    pub fn len(&self) -> usize {
        self.inner.lock().queue.len()
    }

    /// `true` iff no requests are pending.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for NoopScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl IoScheduler for NoopScheduler {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn enqueue(&self, req: BlockRequest) -> u64 {
        let mut g = self.inner.lock();
        let tag = g.next_tag;
        g.next_tag = g.next_tag.saturating_add(1);
        g.queue.push_back(Entry { tag, req });
        tag
    }

    fn pick_next(&self) -> Option<BlockRequest> {
        let mut g = self.inner.lock();
        g.queue.pop_front().map(|e| e.req)
    }

    fn cancel(&self, req_id: u64) -> bool {
        let mut g = self.inner.lock();
        if let Some(pos) = g.queue.iter().position(|e| e.tag == req_id) {
            g.queue.remove(pos);
            true
        } else {
            false
        }
    }
}
