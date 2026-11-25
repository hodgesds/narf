//! `narf_time` for the module: deadlines, timeouts and sleeps on the
//! module-rt monotonic clock (`narf_monotonic_ns`).
//!
//! The kernel's "cycles" are its timer-wheel unit; here they are plain
//! nanoseconds, so `sleep_cycles(wall::ns_to_cycles(ns))` sleeps `ns` as
//! built in. Sleeps complete on the executor's heartbeat (the 1 ms device
//! poller), so their resolution is one heartbeat.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

use narf_module_rt::time as rt;

/// An absolute timeout on the monotonic clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline(rt::Deadline);

impl Deadline {
    pub fn after_ms(ms: u64) -> Self {
        Self(rt::Deadline::after_ms(ms))
    }
    pub fn after_us(us: u64) -> Self {
        Self(rt::Deadline::after_ns(us.saturating_mul(1_000)))
    }
    pub fn after_ns(ns: u64) -> Self {
        Self(rt::Deadline::after_ns(ns))
    }
    pub fn expired(&self) -> bool {
        self.0.expired()
    }
}

/// Nanoseconds on the monotonic clock.
pub fn monotonic_ns() -> u64 {
    rt::now_ns()
}

/// The wall/monotonic conversions the driver names.
pub mod wall {
    /// Nanoseconds to sleep units (identity in the module).
    pub const fn ns_to_cycles(ns: u64) -> u64 {
        ns
    }
    /// Nanoseconds on the monotonic clock.
    pub fn monotonic_ns() -> u64 {
        super::monotonic_ns()
    }
}

/// Nanoseconds to sleep units (identity in the module).
pub const fn ns_to_cycles(ns: u64) -> u64 {
    ns
}

/// Sleep `cycles` (nanoseconds in the module).
pub fn sleep_cycles(cycles: u64) -> rt::SleepUntil {
    rt::sleep_until(rt::Deadline::after_ns(cycles))
}

/// The deadline passed before the future completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elapsed;

/// `narf_time::timeout`: race `fut` against `deadline`.
pub fn timeout<F: Future>(deadline: Deadline, fut: F) -> Timeout<F> {
    Timeout {
        fut: alloc::boxed::Box::pin(fut),
        sleep: rt::sleep_until(deadline.0),
    }
}

/// Future returned by [`timeout`].
#[must_use = "futures do nothing unless polled"]
pub struct Timeout<F> {
    fut: Pin<alloc::boxed::Box<F>>,
    sleep: rt::SleepUntil,
}

impl<F: Future> Future for Timeout<F> {
    type Output = Result<F::Output, Elapsed>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(v) = self.fut.as_mut().poll(cx) {
            return Poll::Ready(Ok(v));
        }
        match Pin::new(&mut self.sleep).poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(Elapsed)),
            Poll::Pending => Poll::Pending,
        }
    }
}
