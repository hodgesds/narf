//! Monotonic time for module code.
//!
//! [`now_ns`] reads the kernel's monotonic clock. The sleep futures here do
//! not register timers — a module has no timer export — they report
//! `Pending` until the deadline passes and rely on the executor's heartbeat
//! (the 1 ms device poller) to be polled again. Their resolution is therefore
//! that heartbeat, which is the same order as the kernel's own `SleepUntil`
//! under a 1 kHz tick.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use crate::abi;

/// Nanoseconds on the kernel's monotonic clock.
pub fn now_ns() -> u64 {
    // SAFETY: argument-free KABI read of a clock.
    unsafe { abi::narf_monotonic_ns() }
}

/// Milliseconds on the kernel's monotonic clock.
pub fn now_ms() -> u64 {
    now_ns() / 1_000_000
}

/// An absolute point on the monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline {
    at_ns: u64,
}

impl Deadline {
    /// The deadline `ns` from now. Saturates rather than wrapping.
    pub fn after_ns(ns: u64) -> Self {
        Self {
            at_ns: now_ns().saturating_add(ns),
        }
    }

    /// The deadline `ms` from now.
    pub fn after_ms(ms: u64) -> Self {
        Self::after_ns(ms.saturating_mul(1_000_000))
    }

    /// An absolute deadline.
    pub const fn at_ns(at_ns: u64) -> Self {
        Self { at_ns }
    }

    /// The deadline's clock value.
    pub const fn as_ns(self) -> u64 {
        self.at_ns
    }

    /// Whether the clock has reached the deadline.
    pub fn expired(self) -> bool {
        now_ns() >= self.at_ns
    }

    /// Nanoseconds left, zero once expired.
    pub fn remaining_ns(self) -> u64 {
        self.at_ns.saturating_sub(now_ns())
    }
}

/// Completes once its [`Deadline`] has passed.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct SleepUntil {
    deadline: Deadline,
}

impl Future for SleepUntil {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.deadline.expired() {
            Poll::Ready(())
        } else {
            // No waker to arm: the executor's heartbeat re-polls.
            Poll::Pending
        }
    }
}

/// Sleep until `deadline`.
pub fn sleep_until(deadline: Deadline) -> SleepUntil {
    SleepUntil { deadline }
}

/// Sleep for `ms` milliseconds.
pub fn sleep_ms(ms: u64) -> SleepUntil {
    sleep_until(Deadline::after_ms(ms))
}

/// Busy-wait `ns` on the monotonic clock. For hardware sequences that
/// mandate a short synchronous delay; never for anything a future could wait
/// on instead, since it holds the calling upcall (and its CPU) for the whole
/// duration.
pub fn spin_ns(ns: u64) {
    let deadline = Deadline::after_ns(ns);
    while !deadline.expired() {
        core::hint::spin_loop();
    }
}

/// Yields to the executor once: `Pending` on the first poll (after asking
/// for another pass), `Ready` on the next.
#[derive(Debug, Default)]
#[must_use = "futures do nothing unless polled"]
pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Yield to the executor once.
pub fn yield_now() -> YieldNow {
    YieldNow::default()
}
