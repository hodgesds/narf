//! Batched reclamation — Stage-4 throughput tuning.
//!
//! Spec: `rcu/specification/spec.md` §3.7. The Stage-3 QSBR path
//! defers a single callback per `defer_drop`; Stage-4 groups
//! callbacks into `ReclaimBatch`es that drain together once a grace
//! period ticks. Grouping cuts the per-callback overhead of the
//! grace-period advance and lets NUMA-aware pacing pick the CPU
//! that actually frees each batch.
//!
//! Stage-4 structural surface:
//! - `ReclaimBatch` aggregates callbacks with a maximum capacity.
//! - `BatchedReclaimer` owns one or more batches; `submit(cb)`
//!   appends to the active batch; `flush()` retires full batches
//!   through the existing QSBR path.
//! - `pace(node_id, quantum)` hints the dispatcher to drain
//!   `node_id`'s batches sooner (used by `power/`'s EnergyAware
//!   path). Stage-4 does not act on the hint; it records it.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Maximum callbacks in a single `ReclaimBatch`. 128 is a compromise:
/// small enough to keep the tail-latency of the drain bounded (one
/// batch = one lock acquire on the reclamation queue), large enough
/// to amortise the grace-period advance.
pub const BATCH_CAP: usize = 128;

type Cb = Box<dyn FnOnce() + Send + 'static>;

/// A batch of pending reclamation callbacks.
pub struct ReclaimBatch {
    callbacks: Vec<Cb>,
    node_id: u16,
}

impl core::fmt::Debug for ReclaimBatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReclaimBatch")
            .field("callbacks", &self.callbacks.len())
            .field("node_id", &self.node_id)
            .finish()
    }
}

impl ReclaimBatch {
    pub fn new(node_id: u16) -> Self {
        Self {
            callbacks: Vec::with_capacity(BATCH_CAP),
            node_id,
        }
    }

    pub fn push(&mut self, cb: Cb) {
        self.callbacks.push(cb);
    }

    pub fn len(&self) -> usize {
        self.callbacks.len()
    }

    pub fn is_full(&self) -> bool {
        self.callbacks.len() >= BATCH_CAP
    }

    pub fn is_empty(&self) -> bool {
        self.callbacks.is_empty()
    }

    /// Run every callback and clear the batch.
    pub fn drain(&mut self) {
        let cbs = core::mem::take(&mut self.callbacks);
        for cb in cbs {
            cb();
        }
    }
}

/// Batched reclaimer owning the currently-active batch.
#[derive(Debug)]
pub struct BatchedReclaimer {
    active: IrqSafeSpinLock<ReclaimBatch>,
    /// Total callbacks submitted across the reclaimer's lifetime —
    /// monotonic. Diagnostic; ops dashboards read it.
    total_submitted: AtomicU64,
    /// Total callbacks that have been drained (executed). `submitted
    /// - drained` is the currently-pending count.
    total_drained: AtomicU64,
    /// Most-recent `pace()` hint for NUMA-aware draining. Stage-4
    /// records but doesn't yet act on it.
    pace_hint_node: AtomicU64,
}

impl BatchedReclaimer {
    pub fn new(node_id: u16) -> Self {
        Self {
            active: IrqSafeSpinLock::new(ReclaimBatch::new(node_id)),
            total_submitted: AtomicU64::new(0),
            total_drained: AtomicU64::new(0),
            pace_hint_node: AtomicU64::new(0),
        }
    }

    /// Append a callback. Returns `true` if the batch is now full
    /// and the caller should `flush()` before further submits.
    pub fn submit<F: FnOnce() + Send + 'static>(&self, cb: F) -> bool {
        self.total_submitted.fetch_add(1, Ordering::Relaxed);
        let mut b = self.active.lock();
        b.push(Box::new(cb));
        b.is_full()
    }

    /// Drain the active batch immediately.
    pub fn flush(&self) {
        let mut b = self.active.lock();
        let n = b.len() as u64;
        b.drain();
        self.total_drained.fetch_add(n, Ordering::Relaxed);
    }

    /// Hint the dispatcher to drain `node_id`'s batches sooner.
    /// `quantum` is the priority weight (higher = sooner); interpret
    /// as relative not absolute — Stage-4 uses the ratio across
    /// reclaimers to pick which to drain first under load.
    pub fn pace(&self, node_id: u16, quantum: u32) {
        let combined = ((node_id as u64) << 32) | (quantum as u64);
        self.pace_hint_node.store(combined, Ordering::Relaxed);
    }

    pub fn pending(&self) -> u64 {
        self.total_submitted
            .load(Ordering::Relaxed)
            .saturating_sub(self.total_drained.load(Ordering::Relaxed))
    }

    pub fn total_submitted(&self) -> u64 {
        self.total_submitted.load(Ordering::Relaxed)
    }
    pub fn total_drained(&self) -> u64 {
        self.total_drained.load(Ordering::Relaxed)
    }
}
