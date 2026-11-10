//! Drive enumeration while retaining its in-flight hardware ownership.

use core::future::Future;
use core::task::Poll;

/// Each hardware operation supplies its own deadline. Do not cancel the
/// owning enumeration future between operations: it may have a live slot
/// or published DMA that its terminal path must disable and reclaim.
pub(crate) async fn run<F, P>(future: F, mut pump: P) -> F::Output
where
    F: Future,
    P: FnMut(),
{
    let mut future = core::pin::pin!(future);
    core::future::poll_fn(|cx| {
        crate::YIELD_TIMEOUT_POLLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        match future.as_mut().poll(cx) {
            Poll::Ready(output) => Poll::Ready(output),
            Poll::Pending => {
                pump();
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    })
    .await
}

/// Enumeration attempts a port gets when its failures are timeouts.
pub(crate) const TIMEOUT_ATTEMPTS: u8 = 2;

/// Charge one failed enumeration attempt against a port's retry budget
/// (`max` attempts for fast failures). An attempt during which a command
/// or control stage ran into its 5 s deadline costs `max / TIMEOUT_ATTEMPTS`
/// of the budget, so a device that never answers is abandoned after
/// `TIMEOUT_ATTEMPTS` attempts instead of `max`. The per-transfer deadline
/// stays at the 5 s a slow-but-working device is entitled to; the bound on
/// how long a dead device can occupy the supervisor comes from retrying
/// less. Linux bounds the same case with `PORT_INIT_TRIES` /
/// `SET_CONFIG_TRIES` in `hub_port_connect`.
pub(crate) const fn charge_failure(count: u8, max: u8, timed_out: bool) -> u8 {
    let cost = if timed_out {
        let share = max / TIMEOUT_ATTEMPTS;
        if share == 0 {
            1
        } else {
            share
        }
    } else {
        1
    };
    let charged = count.saturating_add(cost);
    if charged > max {
        max
    } else {
        charged
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::attach::AttachOutcome;
    use core::cell::Cell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_enumeration_keeps_pending_steps_and_pumps_input() -> TestResult {
        let finished = Cell::new(false);
        let dropped_early = Cell::new(false);
        let pumps = Cell::new(0u64);
        struct OwnedTransfer<'a> {
            finished: &'a Cell<bool>,
            dropped_early: &'a Cell<bool>,
        }
        impl Drop for OwnedTransfer<'_> {
            fn drop(&mut self) {
                if !self.finished.get() {
                    self.dropped_early.set(true);
                }
            }
        }
        let enumerate = async {
            let _transfer = OwnedTransfer {
                finished: &finished,
                dropped_early: &dropped_early,
            };
            // Every simulated command finishes well below the controller's
            // per-operation limit; their valid sequence exceeds 500 ms.
            for _ in 0..6 {
                narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(100_000_000)).await;
            }
            finished.set(true);
            AttachOutcome::Keyboard
        };
        let outcome = narf_scheduler::block_on(run(enumerate, || pumps.set(pumps.get() + 1)));
        if !matches!(outcome, AttachOutcome::Keyboard) || dropped_early.get() {
            return TestResult::Fail("whole-port timeout abandoned valid in-flight enumeration");
        }
        if !finished.get() || pumps.get() == 0 {
            return TestResult::Fail("enumeration did not finish while servicing input");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/enumeration_wait",
        smoke_enumeration_keeps_pending_steps_and_pumps_input
    );

    /// Attempts until a port with budget `max` is abandoned.
    fn attempts(max: u8, timed_out: bool) -> u32 {
        let mut count = 0u8;
        let mut attempts = 0u32;
        while count < max {
            count = charge_failure(count, max, timed_out);
            attempts += 1;
        }
        attempts
    }

    /// With 5 s command/control deadlines a dead device must not get the
    /// full fast-failure budget: timeouts exhaust it in TIMEOUT_ATTEMPTS
    /// attempts, fast failures still get every attempt, and the counter
    /// lands exactly on the budget so the give-up report fires once.
    fn smoke_enumeration_timeouts_exhaust_retry_budget_early() -> TestResult {
        if attempts(8, false) != 8 || attempts(8, true) != u32::from(TIMEOUT_ATTEMPTS) {
            return TestResult::Fail("retry budget not 8 fast failures / 2 timeouts");
        }
        // One timeout then fast failures: half the budget is gone.
        let mut count = charge_failure(0, 8, true);
        let mut more = 0;
        while count < 8 {
            count = charge_failure(count, 8, false);
            more += 1;
        }
        if more != 4 || count != 8 {
            return TestResult::Fail("mixed timeout/fast failures mis-charged");
        }
        if charge_failure(7, 8, true) != 8
            || charge_failure(8, 8, true) != 8
            || charge_failure(0, 1, true) != 1
            || charge_failure(u8::MAX, u8::MAX, false) != u8::MAX
        {
            return TestResult::Fail("retry charge overshot the budget");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usb/enumeration_wait",
        smoke_enumeration_timeouts_exhaust_retry_budget_early
    );
}
