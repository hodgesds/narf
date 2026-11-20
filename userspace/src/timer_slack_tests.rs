//! `select_estimate_accuracy` against fs/select.c, case by case, and the
//! per-park slack choice a poll/select/epoll timeout makes.

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{estimate_accuracy, select_estimate_accuracy, MAX_SLACK_NS};

const MS: u64 = 1_000_000;
const US: u64 = 1_000;

/// 0.1 % of the time left (0.5 % for a niced task), capped at 100 ms, and
/// never below the task slack; a task without slack (real-time) gets none.
fn smoke_select_estimate_accuracy_matches_linux() -> TestResult {
    let cases: [(u64, i32, u64, u64); 9] = [
        // (remaining, nice, task slack, expected)
        (1_000 * MS, 0, 50 * US, 1 * MS),
        (1_000 * MS, 5, 50 * US, 5 * MS),
        (1_500 * MS, 0, 50 * US, 1_500 * US),
        (10 * MS, 0, 50 * US, 50 * US),
        (100_000 * MS, 0, 50 * US, MAX_SLACK_NS),
        (200_000 * MS, 0, 50 * US, MAX_SLACK_NS),
        (30_000 * MS, 1, 50 * US, MAX_SLACK_NS),
        (1_000 * MS, 0, 0, 0),
        (0, 0, 50 * US, 50 * US),
    ];
    for (remaining, nice, slack, want) in cases {
        if select_estimate_accuracy(remaining, nice, slack) != want {
            return TestResult::Fail("select_estimate_accuracy differs from fs/select.c");
        }
    }
    // `__estimate_accuracy` truncates the nanoseconds part on its own.
    if estimate_accuracy(1_000 * MS + 999, 0) != 1 * MS {
        return TestResult::Fail("estimate_accuracy rounds the ns part like Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/timer_slack",
    smoke_select_estimate_accuracy_matches_linux
);

/// A poll/select/epoll timeout parks with its estimated accuracy; any other
/// deadline (nanosleep, futex, a clamped wake) keeps the task slack.
fn smoke_park_slack_follows_the_poll_deadline() -> TestResult {
    let uc = crate::user_task::UserTaskCtx::new();
    let now = 5_000 * MS;
    let deadline = now + 2_000 * MS;
    uc.note_select_timeout(deadline, now, 0);
    if uc.park_slack(deadline) != 2 * MS {
        return TestResult::Fail("a poll timeout did not get its estimated accuracy");
    }
    if uc.park_slack(deadline - 1) != crate::user_task::DEFAULT_TIMER_SLACK_NS {
        return TestResult::Fail("another deadline did not keep the task slack");
    }
    if uc.park_slack(0) != crate::user_task::DEFAULT_TIMER_SLACK_NS {
        return TestResult::Fail("a zero deadline matched the poll slack");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/timer_slack",
    smoke_park_slack_follows_the_poll_deadline
);
