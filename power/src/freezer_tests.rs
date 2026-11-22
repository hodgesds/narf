use super::*;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec;
use core::future::Future;
use core::sync::atomic::AtomicUsize;
use core::task::{Context, Poll};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Counts its wakes.
struct Count(AtomicUsize);
impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
fn counter() -> (Arc<Count>, Waker) {
    let count = Arc::new(Count(AtomicUsize::new(0)));
    (count.clone(), Waker::from(count))
}

static KICKED: IrqSafeSpinLock<Vec<u64>> = IrqSafeSpinLock::new(Vec::new());
fn two_live() -> Vec<u64> {
    vec![101, 102]
}
fn record_kick(task: u64) {
    KICKED.lock().push(task);
}
/// A task that reaches its freeze point as soon as it is kicked.
fn freeze_on_kick(task: u64) {
    KICKED.lock().push(task);
    try_to_freeze(task, Waker::noop());
}

/// Only 102 refuses to freeze.
fn freeze_101_on_kick(task: u64) {
    KICKED.lock().push(task);
    if task == 101 {
        try_to_freeze(task, Waker::noop());
    }
}

fn poll_once<F: Future>(fut: core::pin::Pin<&mut F>) -> Poll<F::Output> {
    fut.poll(&mut Context::from_waker(Waker::noop()))
}
/// Poll until ready, for at most 200 ms (the sleeps between passes are
/// hrtimers a noop waker never hears).
fn drive<F: Future>(mut fut: core::pin::Pin<&mut F>) -> Option<F::Output> {
    let deadline = narf_time::monotonic_ns().saturating_add(200_000_000);
    loop {
        if let Poll::Ready(r) = poll_once(fut.as_mut()) {
            return Some(r);
        }
        if narf_time::monotonic_ns() > deadline {
            return None;
        }
        core::hint::spin_loop();
    }
}

/// A freeze point does nothing without a freeze; during one it holds the
/// task, and a pass kicks only the live tasks not yet frozen. A spurious
/// wake leaves the task frozen; the thaw fires every frozen task's waker
/// once and empties the set.
fn freezer_holds_tasks_until_thaw() -> TestResult {
    let saved = __test_reset();
    install(Hooks {
        live: two_live,
        kick: record_kick,
    });
    KICKED.lock().clear();
    let (count_a, waker_a) = counter();
    let (count_b, waker_b) = counter();
    let idle = !try_to_freeze(101, &waker_a) && !frozen(101);
    FREEZING.store(true, Ordering::Release);
    let first = pass();
    let froze_a = try_to_freeze(101, &waker_a);
    let second = pass();
    let froze_b = try_to_freeze(102, &waker_b) && try_to_freeze(102, &waker_b);
    let third = pass();
    let kicked = KICKED.lock().clone();
    thaw_processes();
    let woke = (
        count_a.0.load(Ordering::Acquire),
        count_b.0.load(Ordering::Acquire),
    );
    let after = !freezing() && !frozen(101) && !frozen(102) && !try_to_freeze(101, &waker_a);
    __test_restore(saved);
    if !idle {
        return TestResult::Fail("a freeze point froze a task with no freeze running");
    }
    if first != [101, 102] || !froze_a || second != [102] || !froze_b || !third.is_empty() {
        return TestResult::Fail("pass did not track the frozen set");
    }
    if kicked != [101, 102, 102] {
        return TestResult::Fail("pass kicked a frozen task or missed one");
    }
    if woke != (1, 1) || !after {
        return TestResult::Fail("thaw did not wake each frozen task once");
    }
    TestResult::Pass
}
kernel_test_in!("power/freezer", freezer_holds_tasks_until_thaw);

/// `freeze_processes` succeeds once every live task froze, keeping them
/// frozen; on a timeout it names the tasks refusing to freeze and thaws
/// the rest. A second freeze during one is refused.
fn freeze_processes_waits_then_times_out() -> TestResult {
    let saved = __test_reset();
    install(Hooks {
        live: two_live,
        kick: freeze_on_kick,
    });
    KICKED.lock().clear();
    let ok = drive(core::pin::pin!(freeze_processes_within(1_000_000_000)));
    let held = freezing() && frozen(101) && frozen(102);
    let again = poll_once(core::pin::pin!(freeze_processes_within(0)));
    thaw_processes();

    install(Hooks {
        live: two_live,
        kick: freeze_101_on_kick,
    });
    let timed_out = drive(core::pin::pin!(freeze_processes_within(5_000_000)));
    let thawed = !freezing() && !frozen(101);
    __test_restore(saved);
    if ok != Some(Ok(())) || !held {
        return TestResult::Fail("freeze_processes did not finish with every task frozen");
    }
    if again != Poll::Ready(Err(FreezeError::InProgress)) {
        return TestResult::Fail("a nested freeze was not refused");
    }
    if timed_out
        != Some(Err(FreezeError::Timeout {
            refusing: vec![102],
        }))
        || !thawed
    {
        return TestResult::Fail("a timeout did not report the tasks and thaw");
    }
    TestResult::Pass
}
kernel_test_in!("power/freezer", freeze_processes_waits_then_times_out);
