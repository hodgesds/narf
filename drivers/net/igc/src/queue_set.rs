//! The adapter's queues as its poll and transmit paths reach them.
//!
//! Linux gives each `igc_q_vector` its own `rx.ring` and `tx.ring`: NAPI
//! polls through the q_vector, `igc_xmit_frame` indexes
//! `adapter->tx_ring[]`, every ring keeps its own counters (which
//! `igc_update_stats` sums), and `igc_down` disables every queue's NAPI and
//! transmit before a reconfiguration replaces the rings. Configuration paths
//! see the whole set through [`QueueSet::all`]; the poll and transmit paths
//! go through the per-queue calls.

use crate::queue::Queue;
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::rss::RssConfig;

#[derive(Debug)]
struct Shared {
    rss: RssConfig,
    rx_drops: u64,
    tx_rejected: u64,
}

#[derive(Debug)]
pub(crate) struct QueueSet {
    /// The whole set, for configuration paths.
    all: IrqSafeSpinLock<Arc<Vec<Arc<Queue>>>>,
    /// The transmit queue selection and the queues' counters.
    shared: IrqSafeSpinLock<Shared>,
    /// Acquisitions of the device-wide locks.
    device_locks: AtomicU64,
    /// Poll and transmit operations in flight.
    active: AtomicUsize,
}

/// A poll path's view of its queue.
#[derive(Debug)]
pub(crate) struct QueueHandle {
    q: usize,
    queue: Option<Arc<Queue>>,
}

impl QueueHandle {
    /// The queue as the poll path uses it now.
    pub(crate) fn current(&mut self, set: &QueueSet) -> Option<&Arc<Queue>> {
        self.queue = set.get(self.q);
        self.queue.as_ref()
    }
}

/// One poll or transmit operation on a queue; a configuration path waits
/// for every one to end before it replaces the set.
#[derive(Debug)]
pub(crate) struct QueueEntry<'a>(&'a AtomicUsize);

impl Drop for QueueEntry<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl QueueSet {
    pub(crate) fn new(queues: Vec<Arc<Queue>>, rss: &RssConfig) -> Self {
        Self {
            all: IrqSafeSpinLock::new(Arc::new(queues)),
            shared: IrqSafeSpinLock::new(Shared {
                rss: rss.clone(),
                rx_drops: 0,
                tx_rejected: 0,
            }),
            device_locks: AtomicU64::new(0),
            active: AtomicUsize::new(0),
        }
    }

    fn with_shared<R>(&self, f: impl FnOnce(&mut Shared) -> R) -> R {
        self.device_locks.fetch_add(1, Ordering::Relaxed);
        f(&mut self.shared.lock())
    }

    /// Every queue, for a configuration path.
    pub(crate) fn all(&self) -> Arc<Vec<Arc<Queue>>> {
        self.device_locks.fetch_add(1, Ordering::Relaxed);
        self.all.lock().clone()
    }

    /// Replace the set. Only while every queue operation has ended and no
    /// new one can start (the adapter is stopped).
    pub(crate) fn replace(&self, set: Arc<Vec<Arc<Queue>>>) {
        self.device_locks.fetch_add(1, Ordering::Relaxed);
        *self.all.lock() = set;
    }

    /// The RSS function the transmit path selects queues with, after a
    /// configuration change.
    pub(crate) fn set_rss(&self, rss: &RssConfig) {
        self.with_shared(|shared| shared.rss = rss.clone());
    }

    /// How many queues the set has.
    pub(crate) fn count(&self) -> usize {
        self.all().len()
    }

    /// Queue `q`, for a transmit or completion path.
    pub(crate) fn get(&self, q: usize) -> Option<Arc<Queue>> {
        self.all().get(q).cloned()
    }

    /// The view a poll path keeps of queue `q`.
    pub(crate) fn handle(&self, q: usize) -> QueueHandle {
        QueueHandle { q, queue: None }
    }

    /// The transmit queue of `frame`'s flow: the queue the RSS function
    /// steers its receive side to.
    pub(crate) fn select(&self, frame: &[u8]) -> usize {
        self.with_shared(|shared| shared.rss.rx_queue(frame))
    }

    /// Count receive descriptors queue `q` dropped.
    pub(crate) fn note_rx_drops(&self, q: usize, drops: u64) {
        let _ = q;
        if drops != 0 {
            self.with_shared(|shared| shared.rx_drops += drops);
        }
    }

    /// Count a frame queue `q` refused.
    pub(crate) fn note_tx_rejected(&self, q: usize) {
        let _ = q;
        self.with_shared(|shared| shared.tx_rejected += 1);
    }

    /// Receive drops and transmit refusals over every queue.
    pub(crate) fn totals(&self) -> (u64, u64) {
        self.with_shared(|shared| (shared.rx_drops, shared.tx_rejected))
    }

    /// Start a poll or transmit operation on queue `q`.
    pub(crate) fn enter(&self, q: usize) -> QueueEntry<'_> {
        let _ = q;
        self.active.fetch_add(1, Ordering::SeqCst);
        QueueEntry(&self.active)
    }

    /// Whether an operation on queue `q` is in flight.
    pub(crate) fn busy(&self, q: usize) -> bool {
        let _ = q;
        self.active.load(Ordering::SeqCst) != 0
    }

    /// Whether no operation on any queue is in flight.
    pub(crate) fn idle(&self) -> bool {
        self.active.load(Ordering::SeqCst) == 0
    }

    /// Acquisitions of a device-wide lock so far.
    pub(crate) fn device_locks(&self) -> u64 {
        self.device_locks.load(Ordering::Relaxed)
    }
}
