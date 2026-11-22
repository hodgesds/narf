//! The adapter's queues as its poll and transmit paths reach them.
//!
//! Linux gives each `igc_q_vector` its own `rx.ring` and `tx.ring`: NAPI
//! polls through the q_vector, `igc_xmit_frame` indexes
//! `adapter->tx_ring[]`, every ring keeps its own counters (which
//! `igc_update_stats` sums), and `igc_down` disables every queue's NAPI and
//! transmit before a reconfiguration replaces the rings. Configuration paths
//! see the whole set through [`QueueSet::all`]; the poll and transmit paths
//! go through the per-queue calls, which touch only that queue's slot and
//! read the RSS function without a lock.

use crate::queue::Queue;
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{fence, AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::rss::RssConfig;

/// Queues an I225/I226 has (`IGC_MAX_RX_QUEUES`, `IGC_MAX_TX_QUEUES`).
pub(crate) const MAX_QUEUES: usize = 4;
/// RSS key bytes the hardware holds (RSSRK).
const KEY_BYTES: usize = 40;
/// RSS redirection-table entries the hardware holds (RETA).
const TABLE_ENTRIES: usize = 128;

/// Queue `q`'s own state: its ring pair, its counters and its operations in
/// flight, on a cache line of its own that only the CPUs using the queue
/// write.
#[derive(Debug)]
#[repr(align(64))]
struct Slot {
    queue: IrqSafeSpinLock<Option<Arc<Queue>>>,
    /// Bumped after each replacement, so a poll path re-reads `queue` only
    /// then.
    generation: AtomicU64,
    active: AtomicUsize,
    rx_drops: AtomicU64,
    tx_rejected: AtomicU64,
}

impl Slot {
    fn new() -> Self {
        Self {
            queue: IrqSafeSpinLock::new(None),
            generation: AtomicU64::new(0),
            active: AtomicUsize::new(0),
            rx_drops: AtomicU64::new(0),
            tx_rejected: AtomicU64::new(0),
        }
    }
}

/// The RSS function as the transmit path reads it: a sequence count around
/// atomic words (a seqlock), republished by configuration paths. Readers
/// write nothing, so selection costs no shared cache-line transfer.
#[derive(Debug)]
struct Steering {
    seq: AtomicU32,
    /// Key bytes, four per word, little-endian.
    key: [AtomicU32; KEY_BYTES / 4],
    key_len: AtomicU32,
    /// Redirection-table entries, four per word, little-endian.
    table: [AtomicU32; TABLE_ENTRIES / 4],
    table_len: AtomicU32,
    /// The function does not fit the words above (`QueueSet::wide` holds
    /// it).
    wide: AtomicBool,
}

impl Steering {
    fn new() -> Self {
        Self {
            seq: AtomicU32::new(0),
            key: core::array::from_fn(|_| AtomicU32::new(0)),
            key_len: AtomicU32::new(0),
            table: core::array::from_fn(|_| AtomicU32::new(0)),
            table_len: AtomicU32::new(0),
            wide: AtomicBool::new(false),
        }
    }

    /// Publish `rss` (or, when it does not fit, that it lives elsewhere).
    /// The caller serializes writers.
    fn publish(&self, rss: &RssConfig, fits: bool) {
        let seq = self.seq.load(Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        if fits {
            for (i, word) in self.key.iter().enumerate() {
                word.store(packed(&rss.key, i), Ordering::Relaxed);
            }
            let key_len = rss.key.len() as u32;
            self.key_len.store(key_len, Ordering::Relaxed);
            for (i, word) in self.table.iter().enumerate() {
                word.store(packed(&rss.indirection, i), Ordering::Relaxed);
            }
            let table_len = rss.indirection.len() as u32;
            self.table_len.store(table_len, Ordering::Relaxed);
        }
        self.wide.store(!fits, Ordering::Relaxed);
        self.seq.store(seq.wrapping_add(2), Ordering::Release);
    }

    /// [`RssConfig::rx_queue`] over the published function; `None` when it
    /// did not fit.
    fn select(&self, frame: &[u8]) -> Option<usize> {
        let mut tuple = [0u8; 36];
        let n = narf_net::rss::flow_tuple(frame, &mut tuple);
        loop {
            let seq = self.seq.load(Ordering::Acquire);
            if seq & 1 != 0 {
                core::hint::spin_loop();
                continue;
            }
            let wide = self.wide.load(Ordering::Relaxed);
            let table_len = self.table_len.load(Ordering::Relaxed) as usize;
            let mut entry = 0;
            if !wide && table_len != 0 && n != 0 {
                let mut key = [0u8; KEY_BYTES];
                for (i, word) in self.key.iter().enumerate() {
                    let bytes = word.load(Ordering::Relaxed).to_le_bytes();
                    key[i * 4..i * 4 + 4].copy_from_slice(&bytes);
                }
                let key_len = self.key_len.load(Ordering::Relaxed) as usize;
                let key = &key[..key_len.min(KEY_BYTES)];
                let hash = narf_net::rss::toeplitz(key, &tuple[..n]) as usize;
                let idx = if table_len.is_power_of_two() {
                    hash & (table_len - 1)
                } else {
                    hash % table_len
                };
                // A torn length is discarded by the sequence check below.
                let idx = idx.min(TABLE_ENTRIES - 1);
                let word = self.table[idx / 4].load(Ordering::Relaxed);
                entry = ((word >> (8 * (idx % 4))) & 0xff) as usize;
            }
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == seq {
                return if wide { None } else { Some(entry) };
            }
        }
    }
}

/// Word `i` of `bytes`, four bytes little-endian, zero past the end.
fn packed(bytes: &[u8], i: usize) -> u32 {
    let mut word = [0u8; 4];
    for (j, byte) in word.iter_mut().enumerate() {
        *byte = bytes.get(i * 4 + j).copied().unwrap_or(0);
    }
    u32::from_le_bytes(word)
}

#[derive(Debug)]
pub(crate) struct QueueSet {
    /// The whole set, for configuration paths.
    all: IrqSafeSpinLock<Arc<Vec<Arc<Queue>>>>,
    /// Acquisitions of the device-wide locks.
    device_locks: AtomicU64,
    /// Queues in the set, for the transmit path's range check.
    count: AtomicUsize,
    slots: [Slot; MAX_QUEUES],
    steering: Steering,
    /// An RSS function wider than the hardware's key or table; serializes
    /// `set_rss`.
    wide: IrqSafeSpinLock<Option<RssConfig>>,
}

/// A poll path's view of its queue.
#[derive(Debug)]
pub(crate) struct QueueHandle {
    q: usize,
    generation: u64,
    queue: Option<Arc<Queue>>,
}

impl QueueHandle {
    /// The queue as the poll path uses it now: re-read from the queue's slot
    /// only after a configuration path replaced it.
    pub(crate) fn current(&mut self, set: &QueueSet) -> Option<&Arc<Queue>> {
        let slot = set.slots.get(self.q)?;
        let generation = slot.generation.load(Ordering::Acquire);
        if generation != self.generation {
            self.queue = slot.queue.lock().clone();
            self.generation = generation;
        }
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
        let set = Self {
            all: IrqSafeSpinLock::new(Arc::new(Vec::new())),
            device_locks: AtomicU64::new(0),
            count: AtomicUsize::new(0),
            slots: core::array::from_fn(|_| Slot::new()),
            steering: Steering::new(),
            wide: IrqSafeSpinLock::new(None),
        };
        set.replace(Arc::new(queues));
        set.set_rss(rss);
        set
    }

    fn slot(&self, q: usize) -> &Slot {
        &self.slots[q.min(MAX_QUEUES - 1)]
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
        for (q, slot) in self.slots.iter().enumerate() {
            *slot.queue.lock() = set.get(q).cloned();
            slot.generation.fetch_add(1, Ordering::Release);
        }
        let count = set.len().min(MAX_QUEUES);
        self.count.store(count, Ordering::Release);
        *self.all.lock() = set;
    }

    /// The RSS function the transmit path selects queues with, after a
    /// configuration change.
    pub(crate) fn set_rss(&self, rss: &RssConfig) {
        self.device_locks.fetch_add(1, Ordering::Relaxed);
        let mut wide = self.wide.lock();
        let fits = rss.key.len() <= KEY_BYTES && rss.indirection.len() <= TABLE_ENTRIES;
        // Stored before the steering words say to look here.
        *wide = (!fits).then(|| rss.clone());
        self.steering.publish(rss, fits);
    }

    /// How many queues the set has.
    pub(crate) fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Queue `q`, for a transmit or completion path: its own slot's lock
    /// only, as `igc_xmit_frame` takes only its ring's transmit lock.
    pub(crate) fn get(&self, q: usize) -> Option<Arc<Queue>> {
        self.slots.get(q)?.queue.lock().clone()
    }

    /// The view a poll path keeps of queue `q`.
    pub(crate) fn handle(&self, q: usize) -> QueueHandle {
        QueueHandle {
            q,
            generation: 0,
            queue: None,
        }
    }

    /// The transmit queue of `frame`'s flow: the queue the RSS function
    /// steers its receive side to.
    pub(crate) fn select(&self, frame: &[u8]) -> usize {
        if let Some(q) = self.steering.select(frame) {
            return q;
        }
        self.device_locks.fetch_add(1, Ordering::Relaxed);
        self.wide
            .lock()
            .as_ref()
            .map_or(0, |rss| rss.rx_queue(frame))
    }

    /// Count receive descriptors queue `q` dropped.
    pub(crate) fn note_rx_drops(&self, q: usize, drops: u64) {
        if drops != 0 {
            self.slot(q).rx_drops.fetch_add(drops, Ordering::Relaxed);
        }
    }

    /// Count a frame queue `q` refused.
    pub(crate) fn note_tx_rejected(&self, q: usize) {
        self.slot(q).tx_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Receive drops and transmit refusals over every queue.
    pub(crate) fn totals(&self) -> (u64, u64) {
        let (mut drops, mut rejected) = (0, 0);
        for slot in &self.slots {
            drops += slot.rx_drops.load(Ordering::Relaxed);
            rejected += slot.tx_rejected.load(Ordering::Relaxed);
        }
        (drops, rejected)
    }

    /// Start a poll or transmit operation on queue `q`, counted on the
    /// queue's own slot.
    pub(crate) fn enter(&self, q: usize) -> QueueEntry<'_> {
        let active = &self.slot(q).active;
        active.fetch_add(1, Ordering::SeqCst);
        QueueEntry(active)
    }

    /// Whether an operation on queue `q` is in flight.
    pub(crate) fn busy(&self, q: usize) -> bool {
        self.slot(q).active.load(Ordering::SeqCst) != 0
    }

    /// Whether no operation on any queue is in flight.
    pub(crate) fn idle(&self) -> bool {
        self.slots
            .iter()
            .all(|slot| slot.active.load(Ordering::SeqCst) == 0)
    }

    /// Acquisitions of a device-wide lock so far.
    pub(crate) fn device_locks(&self) -> u64 {
        self.device_locks.load(Ordering::Relaxed)
    }
}
