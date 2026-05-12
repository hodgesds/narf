//! `wait_for_irq` future — bridges IRQ delivery to the async executor.
//!
//! Usage in a driver:
//!
//! ```ignore
//! let v = narf_interrupts::vector::alloc()?;
//! // … program the device's MSI-X table to deliver `v` …
//! loop {
//!     narf_interrupts::wait_for_irq(v).await;
//!     drain_completion_queue();
//! }
//! ```
//!
//! Race-safety: `WaitForIrq` snapshots `fire_count` on construction
//! (or on first poll) and resolves Ready as soon as the count moves
//! past that watermark. The IRQ handler increments first, then wakes
//! — so the second poll always observes the increment, even if the
//! IRQ landed between waker installation and handler completion.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::dispatch::{clear_waker, fire_count, set_waker};

/// Wait for the next IRQ at `vector`. Returns the post-IRQ fire count
/// (useful for "did I miss any while I was draining the queue" checks).
pub fn wait_for_irq(vector: u8) -> WaitForIrq {
    WaitForIrq {
        vector,
        baseline: fire_count(vector),
    }
}

/// Wait for the next IRQ at `vector`, but bail with `Err(Elapsed)`
/// if `deadline` passes first. Thin wrapper over [`wait_for_irq`]
/// + [`narf_time::timeout`] — drivers that want a wall-clock-bounded
/// IRQ wait should reach for this rather than hand-rolling a
/// `select` between the IRQ future and a `sleep_cycles` future.
///
/// Race-safe in the same way `wait_for_irq` is: the baseline
/// snapshot happens at construction, so an IRQ landing between
/// `wait_for_irq_until(...)` and the first poll still resolves
/// the wait. On timeout the inner `WaitForIrq` is dropped and
/// its waker slot is cleared.
pub fn wait_for_irq_until(
    vector: u8,
    deadline: narf_time::Deadline,
) -> narf_time::Timeout<WaitForIrq> {
    narf_time::timeout(deadline, wait_for_irq(vector))
}

/// Future returned by [`wait_for_irq`].
#[derive(Debug)]
pub struct WaitForIrq {
    vector: u8,
    baseline: u64,
}

impl Future for WaitForIrq {
    type Output = u64;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u64> {
        let now = fire_count(self.vector);
        if now > self.baseline {
            return Poll::Ready(now);
        }
        // Install the waker before the second read. If an IRQ fires
        // between the two reads, it'll either: (a) take the waker we
        // just installed and wake us — we'll be re-polled and the
        // count will exceed baseline; or (b) fire before we install
        // the waker, in which case the second read sees the bumped
        // count and we return Ready immediately.
        set_waker(self.vector, cx.waker().clone());
        let now = fire_count(self.vector);
        if now > self.baseline {
            Poll::Ready(now)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for WaitForIrq {
    fn drop(&mut self) {
        // Avoid leaving a stale waker; otherwise the next IRQ would
        // wake a task that's no longer interested.
        clear_waker(self.vector);
    }
}
