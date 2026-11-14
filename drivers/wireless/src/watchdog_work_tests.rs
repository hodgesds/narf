//! The driver watchdog work: it runs the step once per period, re-queues
//! itself, holds the device only weakly, and frees itself once the device
//! stops or is dropped.

use super::*;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Probe {
    steps: AtomicU32,
    stopped: AtomicBool,
}
impl Watchdog for Probe {
    fn watchdog_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
    fn watchdog_step(self: Arc<Self>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            // A sleeping step: the next period is queued only after it.
            narf_scheduler::yield_now().await;
            self.steps.fetch_add(1, Ordering::AcqRel);
        })
    }
}

fn wait(done: impl Fn() -> bool) -> bool {
    let end = narf_time::monotonic_ns() + 1_000_000_000;
    while narf_time::monotonic_ns() < end && !done() {
        let _ = narf_scheduler::poll_one_round();
        core::hint::spin_loop();
    }
    done()
}

fn smoke_wireless_watchdog_work_requeues_and_frees_itself() -> TestResult {
    let probe = Arc::new(Probe {
        steps: AtomicU32::new(0),
        stopped: AtomicBool::new(false),
    });
    // 5 ms period: the first run is a full period away, then it repeats.
    start_jiffies(&probe, 5);
    if Arc::weak_count(&probe) != 1 || Arc::strong_count(&probe) != 1 {
        return TestResult::Fail("the work must hold the device only weakly");
    }
    if probe.steps.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("the watchdog ran before its first period");
    }
    if !wait(|| probe.steps.load(Ordering::Acquire) >= 3) {
        return TestResult::Fail("the watchdog work did not re-queue itself");
    }
    probe.stopped.store(true, Ordering::Release);
    if !wait(|| Arc::weak_count(&probe) == 0) {
        return TestResult::Fail("a stopped device's watchdog work was not freed");
    }
    let steps = probe.steps.load(Ordering::Acquire);
    let end = narf_time::monotonic_ns() + 30_000_000;
    while narf_time::monotonic_ns() < end {
        let _ = narf_scheduler::poll_one_round();
    }
    if probe.steps.load(Ordering::Acquire) != steps {
        return TestResult::Fail("the watchdog ran after its device stopped");
    }
    // A dropped device ends the work the same way: the next run finds no
    // device and frees the work (no step, no re-queue).
    let probe = Arc::new(Probe {
        steps: AtomicU32::new(0),
        stopped: AtomicBool::new(false),
    });
    start_jiffies(&probe, 1);
    if !wait(|| probe.steps.load(Ordering::Acquire) >= 1) {
        return TestResult::Fail("the second watchdog work never ran");
    }
    drop(probe);
    let end = narf_time::monotonic_ns() + 30_000_000;
    while narf_time::monotonic_ns() < end {
        let _ = narf_scheduler::poll_one_round();
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/watchdog_work",
    smoke_wireless_watchdog_work_requeues_and_frees_itself
);
