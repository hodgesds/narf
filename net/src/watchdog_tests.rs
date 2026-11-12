//! Smokes for the net-device transmit watchdog (`net/watchdog`).

extern crate alloc;

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::watchdog::{DevWatchdog, NetdevWatchdog};

/// A device whose transmit path is stuck while `stuck` is set.
struct FakeNic {
    stuck: AtomicBool,
    checks: AtomicUsize,
    recoveries: AtomicUsize,
    /// CPU the recovery ran on, and whether it ran in task context.
    task_context: AtomicBool,
}

impl NetdevWatchdog for FakeNic {
    fn tx_timed_out(&self, _now: u64) -> bool {
        self.checks.fetch_add(1, Ordering::AcqRel);
        self.stuck.load(Ordering::Acquire)
    }

    fn tx_timeout(&self) {
        self.task_context
            .store(!narf_lib::context::in_irq(), Ordering::Release);
        // `ndo_tx_timeout` recovered the ring.
        self.stuck.store(false, Ordering::Release);
        self.recoveries.fetch_add(1, Ordering::AcqRel);
    }
}

fn rounds_until(ms: u64, mut done: impl FnMut() -> bool) -> bool {
    let end = narf_scheduler::narf_time::monotonic_ns() + ms * 1_000_000;
    while narf_scheduler::narf_time::monotonic_ns() < end {
        let _ = narf_scheduler::poll_one_round();
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    done()
}

/// `dev_watchdog`: the timer checks the device every period; a stuck
/// transmit queues exactly one recovery, run in task context; a healthy
/// device is checked and left alone; once the device is gone the watchdog
/// stops and frees itself.
fn smoke_dev_watchdog_recovers_stuck_tx_from_work() -> TestResult {
    let nic = Arc::new(FakeNic {
        stuck: AtomicBool::new(false),
        checks: AtomicUsize::new(0),
        recoveries: AtomicUsize::new(0),
        task_context: AtomicBool::new(false),
    });
    let weak: Weak<dyn NetdevWatchdog> = Arc::downgrade(&nic) as Weak<dyn NetdevWatchdog>;
    let wd = DevWatchdog::start(weak, 5_000_000);
    let checked = rounds_until(1000, || nic.checks.load(Ordering::Acquire) >= 2);
    let idle_recoveries = nic.recoveries.load(Ordering::Acquire);
    nic.stuck.store(true, Ordering::Release);
    let recovered = rounds_until(1000, || nic.recoveries.load(Ordering::Acquire) == 1);
    let more = rounds_until(30, || nic.recoveries.load(Ordering::Acquire) > 1);
    let fired = wd.fired();
    let armed = wd.is_armed();
    drop(wd);
    // Detached form: stops with the device.
    let probe = Arc::new(FakeNic {
        stuck: AtomicBool::new(false),
        checks: AtomicUsize::new(0),
        recoveries: AtomicUsize::new(0),
        task_context: AtomicBool::new(false),
    });
    DevWatchdog::start_for_device(
        Arc::downgrade(&probe) as Weak<dyn NetdevWatchdog>,
        5_000_000,
    );
    let probed = rounds_until(1000, || probe.checks.load(Ordering::Acquire) >= 1);
    // The watchdog holds the device weakly: dropping it frees it.
    let gone = Arc::downgrade(&probe);
    drop(probe);
    if !checked || idle_recoveries != 0 {
        return TestResult::Fail("a healthy device was not checked, or was recovered");
    }
    if !recovered || more || fired != 1 {
        return TestResult::Fail("a stuck transmit did not get exactly one recovery");
    }
    if !nic.task_context.load(Ordering::Acquire) {
        return TestResult::Fail("ndo_tx_timeout ran outside task context");
    }
    if !armed || !probed || gone.upgrade().is_some() {
        return TestResult::Fail("the watchdog did not keep running, or kept its device alive");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/watchdog",
    smoke_dev_watchdog_recovers_stuck_tx_from_work
);
