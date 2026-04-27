//! Generic IRQ-vector dispatch + waker bridge.
//!
//! Stage-3 / Stage-4 driver-readiness piece: every IRQ that lands in
//! the per-arch trap handler (vector ≥ 32 on x86_64, LPI/SPI INTID
//! mapped to a logical slot on aarch64) increments a 64-bit fire count
//! and wakes the registered task waker, if any.
//!
//! The table is `[Slot; 256]` — one slot per "logical vector." On
//! x86_64 the logical vector *is* the IDT vector. On aarch64 the
//! ITS / GIC layer maps real INTIDs onto a slot index in this table
//! (typically `INTID - LPI_BASE`, capped at 255 in the Stage-3 cut).
//!
//! Per-vector concurrency:
//! - `fire_count` is a single atomic — multiple CPUs delivering the
//!   same vector race only on the increment, never on the value.
//! - `waker` lives behind an `IrqSafeSpinLock` so the IRQ handler can
//!   take the waker out and wake it without leaving anything for the
//!   future to race with on its next poll.

use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Waker;

use narf_lib::sync::IrqSafeSpinLock;

/// Number of logical vectors. Sized to cover the x86_64 IDT range; the
/// aarch64 ITS path stays under 256 LPIs by Stage-3 convention.
pub const NUM_VECTORS: usize = 256;

/// Per-vector dispatch state.
#[derive(Debug)]
pub struct Slot {
    /// Total IRQs delivered on this vector since boot. Never decreases.
    pub fired: AtomicU64,
    /// Task waker that wants to be notified on the next IRQ. Cleared
    /// on every wake — the future re-installs it on its next poll.
    pub waker: IrqSafeSpinLock<Option<Waker>>,
}

impl Slot {
    pub const fn new() -> Self {
        Self {
            fired: AtomicU64::new(0),
            waker: IrqSafeSpinLock::new(None),
        }
    }
}

static SLOTS: [Slot; NUM_VECTORS] = [const { Slot::new() }; NUM_VECTORS];

/// Called from the per-arch IRQ handler with the logical vector that
/// just fired. Increments the fire count + wakes any registered waker.
///
/// Cheap: one atomic increment + one lock acquisition.
#[inline]
pub fn on_irq(vector: u8) {
    let s = &SLOTS[vector as usize];
    s.fired.fetch_add(1, Ordering::Release);
    let waker = s.waker.lock().take();
    if let Some(w) = waker { w.wake(); }
}

/// Snapshot of a vector's fire count. Tasks awaiting the IRQ compare
/// this against an earlier sample to detect a delivered IRQ even when
/// the wake races with a later IRQ.
#[inline]
pub fn fire_count(vector: u8) -> u64 {
    SLOTS[vector as usize].fired.load(Ordering::Acquire)
}

/// Install a waker that will be invoked once on the next IRQ at this
/// vector. A second `set_waker` overwrites without waking the previous
/// one — futures are responsible for not stomping each other (one
/// future per vector is the Stage-3 contract; multiplexing comes
/// later).
#[inline]
pub fn set_waker(vector: u8, w: Waker) {
    *SLOTS[vector as usize].waker.lock() = Some(w);
}

/// Drop any registered waker without waking it. Useful when a future
/// is being dropped before its IRQ fires (cancellation).
#[inline]
pub fn clear_waker(vector: u8) {
    *SLOTS[vector as usize].waker.lock() = None;
}
