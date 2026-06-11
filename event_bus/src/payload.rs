//! Payload model: fixed-size POD `Event` trait + an opt-in
//! `ArenaHandle` for variable-size attachments.
//!
//! The slot in the SPMC ring is `Copy + 'static + Send + Sync` so the
//! producer's `publish()` is a single memcpy and never allocates.
//! Variable-size payloads (uevent text, MTU-sized network frames) use
//! a per-emit arena: the producer reserves an arena buffer, writes
//! bytes, and stores the handle in the fixed-size slot. Subscribers
//! borrow the arena bytes via the handle for the duration of one
//! `recv()`.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Trait for payloads carried in topic slots. Bounded `Copy` so
/// publishing is a memcpy (no Drop on a published slot — Drop-on-
/// overwrite would race with concurrent consumers). The
/// `'static + Send + Sync` lets the slot cross task boundaries.
pub trait Event: Copy + Send + Sync + 'static {}

impl<T: Copy + Send + Sync + 'static> Event for T {}

/// Handle into a per-topic arena. Subscribers `read()` to copy the
/// bytes out — borrowing in place would require the subscriber to
/// keep the arena slot pinned across the wakeup, which is incompatible
/// with the "publisher may overwrite the slot" backpressure rule.
///
/// `ArenaHandle` is `Copy` so it can sit inside a fixed-size topic
/// slot. The actual bytes live in `payload::Arena` keyed by handle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ArenaHandle {
    /// Generation + slot index, packed: `gen << 32 | slot`. Each
    /// arena slot bumps its generation on reuse so a stale handle
    /// is detectable.
    raw: u64,
    /// Length in bytes. The arena slot's capacity is fixed; len
    /// records how many of those bytes the producer actually wrote.
    pub len: u32,
}

impl ArenaHandle {
    /// A handle that resolves to no bytes — used as the in-slot
    /// sentinel when the event has no variable payload.
    pub const EMPTY: Self = Self { raw: 0, len: 0 };

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Per-topic arena for variable-size payloads. Fixed `slots` of
/// `slot_bytes` capacity each; the producer rotates through them in
/// step with the ring. Generation-tagged so subscribers can detect a
/// reused arena slot. The arena is allocated alongside the ring at
/// `create_topic` time.
pub(crate) struct Arena {
    pub slot_bytes: usize,
    pub buf: Box<[u8]>,
    pub slots: Vec<ArenaSlot>,
    pub mask: u64,
    pub head: AtomicU64,
}

pub(crate) struct ArenaSlot {
    pub generation: AtomicU64,
    pub len: AtomicU64,
    pub lock: IrqSafeSpinLock<()>,
}

impl Arena {
    pub fn new(num_slots: usize, slot_bytes: usize) -> Self {
        debug_assert!(num_slots.is_power_of_two() && num_slots > 0);
        let buf = alloc::vec![0u8; num_slots * slot_bytes].into_boxed_slice();
        let mut slots = Vec::with_capacity(num_slots);
        for _ in 0..num_slots {
            slots.push(ArenaSlot {
                generation: AtomicU64::new(1),
                len: AtomicU64::new(0),
                lock: IrqSafeSpinLock::new(()),
            });
        }
        Self {
            slot_bytes,
            buf,
            slots,
            mask: (num_slots - 1) as u64,
            head: AtomicU64::new(0),
        }
    }

    /// Allocate one slot and write `bytes` into it (truncated to
    /// `slot_bytes`). Returns the handle. Wait-free at the producer.
    pub fn write(&self, bytes: &[u8]) -> ArenaHandle {
        let seq = self.head.fetch_add(1, Ordering::AcqRel);
        let idx = (seq & self.mask) as usize;
        let slot = &self.slots[idx];
        let _g = slot.lock.lock();
        let written = bytes.len().min(self.slot_bytes);
        let start = idx * self.slot_bytes;
        let ptr = self.buf.as_ptr() as *mut u8;
        // SAFETY: `start = idx * slot_bytes` with `idx < num_slots`, and
        // `buf.len() == num_slots * slot_bytes`, so the destination range
        // `[start, start + written)` (with `written <= slot_bytes`) lies
        // fully within `buf`. We hold this slot's `IrqSafeSpinLock` for the
        // duration of the copy, so no other producer or reader touches these
        // bytes concurrently; `bytes` is an independent caller-owned slice
        // and cannot overlap `buf`, satisfying `copy_nonoverlapping`.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.add(start), written);
        }
        slot.len.store(written as u64, Ordering::Release);
        let gen = slot.generation.load(Ordering::Acquire);
        ArenaHandle {
            raw: (gen << 32) | (idx as u64 & 0xFFFF_FFFF),
            len: written as u32,
        }
    }

    /// Copy the bytes referenced by `handle` into `out`. Returns the
    /// number of bytes copied, or `None` if the handle is stale
    /// (generation has been bumped — the producer reused the slot).
    pub fn read(&self, handle: ArenaHandle, out: &mut [u8]) -> Option<usize> {
        if handle.len == 0 {
            return Some(0);
        }
        let idx = (handle.raw & 0xFFFF_FFFF) as usize;
        let want_gen = handle.raw >> 32;
        if idx >= self.slots.len() {
            return None;
        }
        let slot = &self.slots[idx];
        let _g = slot.lock.lock();
        let cur_gen = slot.generation.load(Ordering::Acquire);
        if cur_gen != want_gen {
            return None;
        }
        let start = idx * self.slot_bytes;
        let want = (handle.len as usize).min(out.len());
        let ptr = self.buf.as_ptr();
        // SAFETY: idx < num_slots and we hold the slot lock so the
        // bytes aren't being concurrently written.
        unsafe {
            core::ptr::copy_nonoverlapping(ptr.add(start), out.as_mut_ptr(), want);
        }
        Some(want)
    }

    /// Recycle a slot — bump its generation so any extant handle
    /// becomes stale. The producer calls this implicitly via the
    /// rotating-head allocation; here for explicit testing /
    /// future reclaim hooks.
    #[allow(dead_code)]
    pub fn recycle(&self, idx: usize) {
        if idx < self.slots.len() {
            self.slots[idx].generation.fetch_add(1, Ordering::AcqRel);
        }
    }
}

// SAFETY: Arena's interior mutability is guarded by per-slot
// `IrqSafeSpinLock`; the buf bytes are only touched while a slot
// lock is held; slot metadata is atomic.
unsafe impl Send for Arena {}
// SAFETY: same justification as the `Send` impl above. Every shared access
// to the interior `buf` bytes happens only while the corresponding per-slot
// `IrqSafeSpinLock` is held, and all slot metadata (`generation`, `len`,
// `head`) is atomic, so concurrent access from multiple threads is fully
// synchronized.
unsafe impl Sync for Arena {}

impl core::fmt::Debug for Arena {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Arena")
            .field("slot_bytes", &self.slot_bytes)
            .field("slots", &self.slots.len())
            .finish_non_exhaustive()
    }
}
