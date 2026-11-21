//! The USB supervisor's wait between cycles.
//!
//! Each controller's supervisor sleeps here between its port/hub passes.
//! It wakes on a kick of its controller (`Xhci::kick_supervisor`: a Port
//! Status Change Event, a queued Transfer Event such as a HID report or a
//! hub status-change completion, a controller error, or an API caller with
//! work for it) and, today, also every 8 ms on a timer-wheel sleep.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

/// Today's fallback: the supervisor re-samples every 8 ms on the wheel.
const LEGACY_FALLBACK_MS: u64 = 8;

/// What the supervisor's wait can observe of its controller.
pub(crate) trait KickSource: Sync {
    /// Kicks so far; a wait ends when this moves past the value it saw.
    fn kicks(&self) -> u64;
    /// Register `waker` under `id` for the next kick and return whether a
    /// kick newer than `seen` has already happened.
    fn arm(&self, id: u64, waker: &Waker, seen: u64) -> bool;
    /// Drop the registration of `id`.
    fn disarm(&self, id: u64);
    /// Work is queued for the supervisor's pumps.
    fn pending(&self) -> bool {
        false
    }
}

impl KickSource for crate::xhci::Xhci {
    fn kicks(&self) -> u64 {
        self.supervisor_kicks()
    }
    fn arm(&self, id: u64, waker: &Waker, seen: u64) -> bool {
        self.arm_supervisor_wait(id, waker, seen)
    }
    fn disarm(&self, id: u64) {
        self.disarm_supervisor_wait(id);
    }
    fn pending(&self) -> bool {
        self.has_pending_transfer_events()
    }
}

/// Why a wait ended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Woke {
    /// The controller was kicked.
    Kick,
    /// The wait's deadline passed.
    Deadline,
}

/// What the supervisor has to wait out, besides kicks.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Needs {
    /// Monotonic ns at which the earliest bound downstream port's idle
    /// window ends (`attach::next_idle_suspend_ns`).
    pub idle_suspend_at_ns: Option<u64>,
    /// A source of change that cannot interrupt (a controller without
    /// MSI-X/MSI/INTx, a hub without a status-change endpoint) is
    /// re-sampled at this interval.
    pub poll_every_ms: Option<u64>,
    /// Monotonic ns at which a failed step (a controller recovery that
    /// could not run) is retried.
    pub retry_at_ns: Option<u64>,
}

/// The deadline the supervisor's wait arms for `needs`, if any.
pub(crate) fn next_deadline(now_ns: u64, needs: &Needs) -> Option<narf_time::Deadline> {
    let _ = (now_ns, needs);
    Some(narf_time::Deadline::after_ms(LEGACY_FALLBACK_MS))
}

static NEXT_WAITER: AtomicU64 = AtomicU64::new(1);

/// The supervisor's wait: see [`park`].
pub(crate) struct Park<'a, S: KickSource> {
    source: &'a S,
    id: u64,
    seen: u64,
    deadline: Option<narf_time::Deadline>,
    sleep: Option<narf_time::SleepUntil>,
}

/// Wait for a kick of `source` newer than `seen`, or `deadline`.
pub(crate) fn park<S: KickSource>(
    source: &S,
    seen: u64,
    deadline: Option<narf_time::Deadline>,
) -> Park<'_, S> {
    Park {
        source,
        id: NEXT_WAITER.fetch_add(1, Ordering::Relaxed),
        seen,
        deadline,
        sleep: None,
    }
}

impl<S: KickSource> Park<'_, S> {
    /// Whether this wait armed a timer.
    pub(crate) fn timer_armed(&self) -> bool {
        self.sleep.is_some()
    }
}

impl<S: KickSource> Future for Park<'_, S> {
    type Output = Woke;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Woke> {
        let this = self.get_mut();
        if this.source.arm(this.id, cx.waker(), this.seen) || this.source.pending() {
            return Poll::Ready(Woke::Kick);
        }
        // Today's wait re-samples on an 8 ms wheel sleep, whatever the
        // supervisor's own deadline.
        let _ = this.deadline;
        let sleep = this
            .sleep
            .get_or_insert_with(|| narf_time::sleep_ms(LEGACY_FALLBACK_MS));
        match Pin::new(sleep).poll(cx) {
            Poll::Ready(()) => Poll::Ready(Woke::Deadline),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: KickSource> Drop for Park<'_, S> {
    fn drop(&mut self) {
        self.source.disarm(self.id);
    }
}

#[cfg(feature = "kernel-test")]
#[path = "supervisor_wait_tests.rs"]
mod tests;
