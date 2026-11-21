//! The USB supervisor's wait between cycles, event-driven as Linux's
//! `hub_wq` is: `hub_event` runs only when kicked — `hub_irq` when a
//! hub's status-change URB completes, the roothub after a Port Status
//! Change Event, an explicit `kick_hub_wq` — and HID input arrives by URB
//! completion (`hid_irq_in`).
//!
//! The wait ends on a kick of the supervisor's controller
//! (`Xhci::kick_supervisor`: a Port Status Change Event, a queued
//! Transfer Event such as a HID report or a hub status-change completion,
//! a controller error, or an API caller with work for its pumps), and
//! otherwise only at a deadline the supervisor has of its own
//! ([`Needs`]): an idle-suspend window ending, a source of change that
//! cannot interrupt and must be re-sampled, a failed step to retry. With
//! none, it arms no timer at all.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

/// Re-sample interval for a hub without a status-change endpoint: the
/// period of Linux's roothub status timer (`usb_hcd_poll_rh_status`,
/// `HZ / 4`).
pub(crate) const POLL_INTERVAL_MS: u64 = 250;
/// Re-sample interval for a controller without any interrupt (MSI-X,
/// MSI and INTx all unavailable): its events are seen only when something
/// drains the ring, so the supervisor keeps the input cadence it always
/// had there.
pub(crate) const NO_IRQ_POLL_MS: u64 = 8;

/// What the supervisor's wait can observe of its controller.
pub(crate) trait KickSource: Sync {
    /// Kicks so far; a wait ends when this moves past the value it saw.
    /// Read only by the kernel tests; production reads the count directly
    /// (`Xhci::supervisor_kicks`) before parking.
    #[cfg(feature = "kernel-test")]
    fn kicks(&self) -> u64;
    /// Register `waker` under `id` for the next kick and return whether a
    /// kick newer than `seen` has already happened.
    fn arm(&self, id: u64, waker: &Waker, seen: u64) -> bool;
    /// Drop the registration of `id`.
    fn disarm(&self, id: u64);
}

impl KickSource for crate::xhci::Xhci {
    #[cfg(feature = "kernel-test")]
    fn kicks(&self) -> u64 {
        self.supervisor_kicks()
    }
    fn arm(&self, id: u64, waker: &Waker, seen: u64) -> bool {
        self.arm_supervisor_wait(id, waker, seen)
    }
    fn disarm(&self, id: u64) {
        self.disarm_supervisor_wait(id);
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

/// The deadline the supervisor's wait arms for `needs`: the earliest of
/// them, exactly, or none at all.
pub(crate) fn next_deadline(now_ns: u64, needs: &Needs) -> Option<narf_time::Deadline> {
    let poll_at = needs
        .poll_every_ms
        .map(|ms| now_ns.saturating_add(ms.saturating_mul(1_000_000)));
    let at = [needs.idle_suspend_at_ns, needs.retry_at_ns, poll_at]
        .into_iter()
        .flatten()
        .min()?;
    Some(narf_time::Deadline::after_ns(at.saturating_sub(now_ns)))
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

/// Wait for a kick of `source` newer than `seen`, or `deadline`. A wait
/// without a deadline arms no timer.
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
    /// Whether this wait armed a timer (read by the kernel tests).
    #[cfg(feature = "kernel-test")]
    pub(crate) fn timer_armed(&self) -> bool {
        self.sleep.is_some()
    }
}

impl<S: KickSource> Future for Park<'_, S> {
    type Output = Woke;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Woke> {
        let this = self.get_mut();
        // Registered before the check: a kick after it wakes this waker,
        // one before it is seen in the count.
        if this.source.arm(this.id, cx.waker(), this.seen) {
            return Poll::Ready(Woke::Kick);
        }
        let Some(deadline) = this.deadline else {
            return Poll::Pending;
        };
        if deadline.expired() {
            return Poll::Ready(Woke::Deadline);
        }
        // An hrtimer for exactly that deadline.
        let sleep = this
            .sleep
            .get_or_insert_with(|| narf_time::sleep_until(deadline));
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
