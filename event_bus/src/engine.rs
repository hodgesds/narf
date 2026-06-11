//! SPMC ring engine — one producer, many cursored consumers.
//!
//! The Disruptor publish step minus the publisher-waits-on-slowest
//! policy: the producer claims a monotonic sequence number, writes a
//! slot, and publishes via release-store of the slot's per-slot
//! `seq`. Consumers carry independent `Cursor`s and read by
//! acquire-loading the slot at `cursor & (N - 1)` and checking `seq`.
//!
//! Slot recycling: producer never blocks. When the ring is "full"
//! (head - min_cursor >= N), the producer overwrites the oldest slot
//! anyway; the trailing consumer's next read detects `slot.seq >
//! expected_seq` and returns `RecvError::Gapped { skipped }` with
//! its cursor fast-forwarded.
//!
//! Cache-line discipline: `head`, every cursor entry, and the slot
//! array each sit on their own 64-byte line via `Align64`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::Waker;

use narf_lib::sync::IrqSafeSpinLock;

/// 64-byte alignment wrapper to keep producer / consumer / slots on
/// disjoint cache lines.
#[repr(C, align(64))]
pub(crate) struct Align64<T>(pub T);

/// Per-topic monotonic sequence number stamped on every published event.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SeqNum(pub u64);

/// One ring slot. `seq` doubles as the publish handshake:
/// - producer reserves slot at sequence `s`, slot's `seq` is set to
///   `s` (publish complete) after the payload is written.
/// - consumer waiting for sequence `s` reads slot at `s & mask` and
///   inspects `seq`. If `seq == s`, payload is good. If `seq > s`,
///   producer has wrapped — gap detected.
pub(crate) struct Slot<T> {
    pub seq: AtomicU64,
    pub val: UnsafeCell<MaybeUninit<T>>,
}

impl<T> Slot<T> {
    pub const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
            val: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

/// One subscriber's cursor entry inside the ring. `live = false` once
/// the subscriber is dropped or its cap is revoked, so the producer
/// can skip it when computing `min_cursor` for diagnostics.
pub(crate) struct CursorEntry {
    pub cursor: AtomicU64,
    pub live: AtomicBool,
    pub waker: IrqSafeSpinLock<Option<Waker>>,
}

impl CursorEntry {
    pub fn new() -> Self {
        Self {
            cursor: AtomicU64::new(0),
            live: AtomicBool::new(true),
            waker: IrqSafeSpinLock::new(None),
        }
    }
}

/// Bounded SPMC ring shared between publisher and all subscribers via
/// `Arc`. Generic over payload `T` (stored by value in slots) and
/// fixed capacity `N` (must be a power of two).
#[repr(C)]
pub(crate) struct Ring<T: Copy> {
    /// Next publish sequence. Producer-owned cache line.
    pub head: Align64<AtomicU64>,
    /// Latches once the producer cap is revoked.
    pub closed: Align64<AtomicBool>,
    /// Active cursors. Grow-only — entries flip `live=false` on drop,
    /// new subscribers reuse dead slots first.
    pub cursors: IrqSafeSpinLock<Vec<Arc<CursorEntry>>>,
    /// Fixed N slots, allocated on the heap behind `Box<[Slot<T>]>`
    /// since `N` is a runtime-known value passed via `capacity`.
    /// Cache-aligned at outer level via `Align64`.
    pub slots: Align64<Box<[Slot<T>]>>,
    /// `capacity - 1`, since `capacity` is a power of two.
    pub mask: u64,
    /// Capacity in slots.
    pub capacity: u64,
}

// SAFETY: `T: Copy + Send + Sync` is the bound on the Event trait. All
// access to `Slot::val` is guarded by the `seq` handshake (the
// producer writes the payload before publishing `seq`, the consumer
// loads `seq` with Acquire and only reads the payload if the seq
// matches its expected value, which is the same release-acquire pair
// that backs the existing `narf_ipc::spmc_ring`).
unsafe impl<T: Copy + Send + Sync> Send for Ring<T> {}
// SAFETY: same justification as the `Send` impl above. `T: Send + Sync`
// and every shared access to `Slot::val` goes through the release-acquire
// `seq` handshake (producer writes payload then publishes `seq` with
// Release; consumers load `seq` with Acquire and only read the payload on a
// matching seq), so no torn or racing reads of the payload are possible
// across threads.
unsafe impl<T: Copy + Send + Sync> Sync for Ring<T> {}

impl<T: Copy + Send + Sync> Ring<T> {
    /// Allocate a ring with `capacity` slots. `capacity` must be a
    /// power of two; the caller in `topic.rs` enforces this.
    pub fn new(capacity: usize) -> Self {
        debug_assert!(capacity.is_power_of_two() && capacity > 0);
        let mut slots: Vec<Slot<T>> = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(Slot::new());
        }
        Self {
            head: Align64(AtomicU64::new(0)),
            closed: Align64(AtomicBool::new(false)),
            cursors: IrqSafeSpinLock::new(Vec::new()),
            slots: Align64(slots.into_boxed_slice()),
            mask: (capacity - 1) as u64,
            capacity: capacity as u64,
        }
    }

    /// Register a new cursor at the current head — subscribers start
    /// at "no history", first event delivered will be the next one
    /// published.
    pub fn attach_cursor(&self) -> Arc<CursorEntry> {
        let start = self.head.0.load(Ordering::Acquire);
        let entry = Arc::new(CursorEntry::new());
        entry.cursor.store(start, Ordering::Release);
        let mut g = self.cursors.lock();
        // Recycle a dead slot if one exists, otherwise push.
        for existing in g.iter_mut() {
            if !existing.live.load(Ordering::Acquire) {
                *existing = entry.clone();
                return entry;
            }
        }
        g.push(entry.clone());
        entry
    }

    /// Mark a cursor dead so the producer skips it (and so the
    /// `Drop` of `Subscriber` doesn't have to walk the cursor vec
    /// every time).
    pub fn detach_cursor(&self, entry: &Arc<CursorEntry>) {
        entry.live.store(false, Ordering::Release);
        // Wake the cursor's task one last time so any pending future
        // notices and returns `Err(Revoked)` (or whichever close
        // condition surfaces).
        let mut g = entry.waker.lock();
        if let Some(w) = g.take() {
            drop(g);
            w.wake();
        }
    }

    /// Mark the ring closed (publisher cap revoked). Wakes every
    /// cursor so pending `next()` futures wake up and observe the
    /// closure.
    pub fn close(&self) {
        self.closed.0.store(true, Ordering::Release);
        let g = self.cursors.lock();
        for c in g.iter() {
            if c.live.load(Ordering::Acquire) {
                let mut wg = c.waker.lock();
                if let Some(w) = wg.take() {
                    drop(wg);
                    w.wake();
                }
            }
        }
    }

    /// Publish `event`, returning its sequence number. Wait-free at
    /// the producer (single-owner publisher cap implies no contention
    /// for `head`). Overwrites the oldest live slot if every cursor
    /// is behind by ≥ capacity; trailing consumers detect via gap.
    pub fn publish(&self, event: T) -> SeqNum {
        // Single-producer: relaxed read + release store via head's
        // monotonic increment. We use fetch_add for forward
        // compatibility if we ever want to weaken the single-producer
        // assumption later (e.g. internal multi-producer audit hook).
        let seq = self.head.0.fetch_add(1, Ordering::AcqRel);
        let idx = (seq & self.mask) as usize;
        let slot = &self.slots.0[idx];

        // Bump the slot's seq to an "in-progress" (odd) marker, write
        // the payload, then release-store the final published seq.
        // The seqlock-style pattern lets a reader detect a torn
        // publish even on a relaxed-architecture and skip the slot.
        let publish_marker = seq.wrapping_mul(2).wrapping_add(1);
        let final_seq = seq.wrapping_mul(2).wrapping_add(2);
        // Step 1: mark slot in-progress.
        slot.seq.store(publish_marker, Ordering::Release);
        // Step 2: write payload. SAFETY: producer is single-owner,
        // and the seq handshake stops consumers from racing.
        unsafe {
            (*slot.val.get()).write(event);
        }
        // Step 3: publish.
        slot.seq.store(final_seq, Ordering::Release);

        // Wake any parked cursors. Snapshot the wakers under the
        // cursors-lock and drop the lock before waking.
        let wakers: Vec<Waker> = {
            let g = self.cursors.lock();
            let mut v = Vec::new();
            for c in g.iter() {
                if c.live.load(Ordering::Acquire) {
                    let mut wg = c.waker.lock();
                    if let Some(w) = wg.take() {
                        v.push(w);
                    }
                }
            }
            v
        };
        for w in wakers {
            w.wake();
        }

        SeqNum(seq)
    }

    /// Try to receive at `entry`'s cursor.
    ///
    /// Returns one of:
    /// - `TryRecvOk::Empty` — ring head not advanced past cursor.
    /// - `TryRecvOk::Got { seq, val }` — payload + its sequence.
    /// - `TryRecvOk::Gapped { skipped }` — cursor was overwritten;
    ///   cursor is fast-forwarded to `head - capacity + 1`.
    /// - `TryRecvOk::Closed` — publisher gone, ring drained.
    /// - `TryRecvOk::Revoked` — this subscriber's cursor is dead.
    pub fn try_recv(&self, entry: &CursorEntry) -> TryRecvOk<T> {
        if !entry.live.load(Ordering::Acquire) {
            return TryRecvOk::Revoked;
        }
        let head = self.head.0.load(Ordering::Acquire);
        let cursor = entry.cursor.load(Ordering::Acquire);
        if cursor >= head {
            if self.closed.0.load(Ordering::Acquire) {
                return TryRecvOk::Closed;
            }
            return TryRecvOk::Empty;
        }
        // We expect the slot at `cursor & mask` to have published seq
        // == cursor * 2 + 2. If the slot's seq has moved further on
        // (producer wrapped past us), report a gap and fast-forward.
        let idx = (cursor & self.mask) as usize;
        let slot = &self.slots.0[idx];
        let expected_final = cursor.wrapping_mul(2).wrapping_add(2);
        loop {
            let s = slot.seq.load(Ordering::Acquire);
            if s == expected_final {
                // SAFETY: producer published this seq via Release,
                // we Acquire-loaded the seq, so the payload write is
                // visible. T: Copy means we don't move out of the slot.
                let val = unsafe { (*slot.val.get()).assume_init_read() };
                // Re-check seq AFTER read to detect a torn read
                // (producer wrapped past us during the copy).
                let s2 = slot.seq.load(Ordering::Acquire);
                if s2 != expected_final {
                    // Got overwritten mid-read — treat as gap. Fall
                    // through to the gap path below.
                    return self.gap_fast_forward(entry, head);
                }
                entry.cursor.store(cursor + 1, Ordering::Release);
                return TryRecvOk::Got {
                    seq: SeqNum(cursor),
                    val,
                };
            } else if s > expected_final {
                // Producer wrapped past us.
                return self.gap_fast_forward(entry, head);
            } else {
                // Slot still being written (in-progress marker
                // present, or not yet caught up). Spin briefly — this
                // is a single-producer ring so the in-progress window
                // is one memcpy of T.
                core::hint::spin_loop();
            }
        }
    }

    /// Compute the new cursor position after a detected gap and
    /// return the gap signal. New cursor = head - capacity + 1 so
    /// the next read picks up the most recent slot the producer is
    /// guaranteed not to have overwritten.
    fn gap_fast_forward(&self, entry: &CursorEntry, head: u64) -> TryRecvOk<T> {
        let old = entry.cursor.load(Ordering::Acquire);
        let resync = head.saturating_sub(self.capacity).saturating_add(1);
        let skipped = resync.saturating_sub(old);
        entry.cursor.store(resync, Ordering::Release);
        TryRecvOk::Gapped { skipped }
    }

    /// Register a waker on `entry` so a publish wakes it. Called by
    /// the async surface when `try_recv` returns Empty.
    pub fn park(&self, entry: &CursorEntry, waker: &Waker) {
        let mut g = entry.waker.lock();
        // Replace any prior waker — the executor passes a fresh one
        // each poll, and the old one is stale.
        *g = Some(waker.clone());
    }
}

/// Outcome of a non-blocking `try_recv`.
#[derive(Debug)]
pub enum TryRecvOk<T> {
    Empty,
    Got { seq: SeqNum, val: T },
    Gapped { skipped: u64 },
    Closed,
    Revoked,
}
