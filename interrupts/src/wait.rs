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
use core::task::{Context, Poll, Waker};

use crate::dispatch::{clear_waker, fire_count, set_waker};

/// Wait for the next IRQ at `vector`. Returns the post-IRQ fire count
/// (useful for "did I miss any while I was draining the queue" checks).
pub fn wait_for_irq(vector: u8) -> WaitForIrq {
    WaitForIrq {
        vector,
        baseline: fire_count(vector),
        waker: None,
    }
}

/// Wait for the next IRQ at `vector`, but bail with `Err(Elapsed)`
/// if `deadline` passes first. Thin wrapper over [`wait_for_irq`]
/// composed with [`narf_time::timeout`] — drivers that want a
/// wall-clock-bounded IRQ wait should reach for this rather than hand-rolling a
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
    /// Cached clone of the waker we handed to `set_waker`. Stored so
    /// `Drop` can pass it to `clear_waker` and remove ONLY this
    /// future's registration — leaving other tasks parked on the
    /// same vector (shared MSI-X / level-INTx is the common case)
    /// untouched. `None` until the first `poll`.
    waker: Option<Waker>,
}

impl Future for WaitForIrq {
    type Output = u64;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u64> {
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
        let w = cx.waker().clone();
        set_waker(self.vector, w.clone());
        // Remember our waker so Drop can clear exactly this entry.
        // `set_waker` dedups via `will_wake`, so re-polling with the
        // same waker is idempotent on the dispatch side; the cached
        // copy here is just so Drop has a `&Waker` to hand back.
        self.waker = Some(w);
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
        // wake a task that's no longer interested. Only clear OUR
        // waker — other tasks may share this vector (shared MSI-X /
        // level-INTx) and their wakers must survive.
        if let Some(w) = self.waker.as_ref() {
            clear_waker(self.vector, w);
        }
    }
}
