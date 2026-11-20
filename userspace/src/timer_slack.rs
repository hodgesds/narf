//! Per-task timer slack: `select_estimate_accuracy` (fs/select.c), the
//! real-time rule of `__setscheduler_params` (kernel/sched/syscalls.c) and
//! `/proc/<pid>/timerslack_ns` (fs/proc/base.c).
//!
//! `current->timer_slack_ns` (`UserTaskCtx::timer_slack_ns`) widens every
//! hrtimer a task parks on. `nanosleep` and futex waits take it as is; a
//! `poll` / `select` / `epoll_wait` timeout takes `select_estimate_accuracy`
//! of the time left — 0.1 % of it (0.5 % for a niced task), at most 100 ms,
//! never less than the task slack — so a long poll timeout shares its
//! interrupt with everything else due in that window.

use core::sync::atomic::Ordering;

use narf_filesystem::FsError;

/// `MAX_SLACK` (fs/select.c): 100 ms.
pub const MAX_SLACK_NS: u64 = 100 * 1_000_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;

/// `__estimate_accuracy` of a timeout with `remaining_ns` left: 0.1 % of it,
/// 0.5 % when `nice > 0`, capped at [`MAX_SLACK_NS`].
pub fn estimate_accuracy(remaining_ns: u64, nice: i32) -> u64 {
    let divfactor: u64 = if nice > 0 { 1000 / 5 } else { 1000 };
    let (sec, nsec) = (remaining_ns / NSEC_PER_SEC, remaining_ns % NSEC_PER_SEC);
    if sec > MAX_SLACK_NS / (NSEC_PER_SEC / divfactor) {
        return MAX_SLACK_NS;
    }
    let slack = nsec / divfactor + sec * (NSEC_PER_SEC / divfactor);
    slack.min(MAX_SLACK_NS)
}

/// `select_estimate_accuracy`: the slack of a poll/select/epoll timeout with
/// `remaining_ns` left, for a task with `task_slack_ns` and `nice`. A task
/// with no slack (real-time) gets none.
pub fn select_estimate_accuracy(remaining_ns: u64, nice: i32, task_slack_ns: u64) -> u64 {
    if task_slack_ns == 0 {
        return 0;
    }
    estimate_accuracy(remaining_ns, nice).max(task_slack_ns)
}

/// `__setscheduler_params`: a real-time task has no timer slack; leaving
/// real-time restores the default if the slack was 0.
pub(crate) fn apply_policy(task: u64, realtime: bool) {
    let _ = crate::task::try_with_task(task, |t| {
        let uc = &t.uctx;
        if realtime {
            uc.timer_slack_ns.store(0, Ordering::Relaxed);
        } else if uc.timer_slack_ns.load(Ordering::Relaxed) == 0 {
            uc.timer_slack_ns.store(
                uc.default_timer_slack_ns.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
        }
    });
}

/// Whether `task` runs a real-time policy (`rt_or_dl_task_policy`).
fn is_realtime(task: u64) -> bool {
    narf_scheduler::user_scheduling(narf_scheduler::TaskId(task)).is_some_and(|s| {
        matches!(
            s.policy,
            narf_scheduler::UserPolicy::Fifo | narf_scheduler::UserPolicy::RoundRobin
        )
    })
}

/// `timerslack_ns_show` / `_write`'s access rule: a task may always reach
/// its own; another task's needs `CAP_SYS_NICE` over that task's user
/// namespace (`ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE)`).
fn may_access(task: u64) -> bool {
    crate::handlers::current_task_id() == task
        || crate::handlers::capable_over_task(task, crate::handlers::CAP_SYS_NICE)
}

/// `/proc/<pid>/timerslack_ns` read: the task's current slack.
pub fn proc_timerslack_get(pid: u64) -> Result<u64, FsError> {
    let task = crate::handlers::proc_pid_to_tid(pid);
    let slack =
        crate::task::try_with_task(task, |t| t.uctx.timer_slack()).ok_or(FsError::NotFound)?;
    if !may_access(task) {
        return Err(FsError::OperationNotPermitted);
    }
    Ok(slack)
}

/// `/proc/<pid>/timerslack_ns` write: set the slack; 0 restores the task's
/// default, and a real-time task keeps 0 whatever is written.
pub fn proc_timerslack_set(pid: u64, slack_ns: u64) -> Result<(), FsError> {
    let task = crate::handlers::proc_pid_to_tid(pid);
    if crate::task::try_with_task(task, |_| ()).is_none() {
        return Err(FsError::NotFound);
    }
    if !may_access(task) {
        return Err(FsError::OperationNotPermitted);
    }
    let realtime = is_realtime(task);
    crate::task::try_with_task(task, |t| {
        let uc = &t.uctx;
        let slack = if realtime {
            0
        } else if slack_ns == 0 {
            uc.default_timer_slack_ns.load(Ordering::Relaxed)
        } else {
            slack_ns
        };
        uc.timer_slack_ns.store(slack, Ordering::Relaxed);
    })
    .ok_or(FsError::NotFound)
}

#[path = "timer_slack_tests.rs"]
mod tests;
