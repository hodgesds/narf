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
            // Every simulated command finishes below the controller's 250 ms
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
}
