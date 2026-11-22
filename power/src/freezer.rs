//! The task freezer: Linux's `freeze_processes` and `thaw_processes`
//! (`kernel/power/process.c`), with the per-task half of
//! `kernel/freezer.c`.
//!
//! This module owns the freezer's state. The user-task runtime in
//! `narf-userspace` supplies the tasks: it installs [`Hooks`] (the live
//! user tasks, and a wake for one of them, Linux's `fake_signal_wake_up`)
//! and calls [`try_to_freeze`] at its freeze points. There are two:
//! - a user task's first poll, before it enters user mode;
//! - the top of each interruptible park loop (the own-stack park and
//!   `wait4`'s), Linux's `TASK_FREEZABLE` sleeps.
//!
//! A task running in user mode reaches one at its next timer tick, which
//! yields to the executor while [`freezing`] holds, even with nothing else
//! runnable. A frozen task is resumed only by [`thaw_processes`]; any other
//! wake, `SIGKILL` included, finds it still frozen, as Linux's
//! `TASK_FROZEN` does.
//!
//! A task in an uninterruptible kernel wait (a synchronous filesystem read,
//! a lock) is not frozen there, as Linux does not freeze
//! `TASK_UNINTERRUPTIBLE` sleepers. The freezer waits for it to finish and
//! reach a freeze point. That keeps a frozen task from holding a lock that
//! device freezing or the image writer needs.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

use narf_lib::sync::IrqSafeSpinLock;

/// `freeze_timeout_msecs`: how long [`freeze_processes`] waits for every
/// task to reach a freeze point.
pub const FREEZE_TIMEOUT_MS: u64 = 20_000;

/// What the freezer needs from the task runtime.
#[derive(Clone, Copy, Debug)]
pub struct Hooks {
    /// Every freezable task that has not exited.
    pub live: fn() -> Vec<u64>,
    /// Wake one so it reaches a freeze point (`fake_signal_wake_up`).
    pub kick: fn(u64),
}

/// Why [`freeze_processes`] failed. Either way the system is thawed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FreezeError {
    /// A freeze is already in progress.
    InProgress,
    /// These tasks did not reach a freeze point within the timeout
    /// (Linux's "tasks refusing to freeze").
    Timeout { refusing: Vec<u64> },
}

static HOOKS: IrqSafeSpinLock<Option<Hooks>> = IrqSafeSpinLock::new(None);
/// `pm_freezing`.
static FREEZING: AtomicBool = AtomicBool::new(false);
/// The frozen tasks, each with the waker that thaws it.
static FROZEN: IrqSafeSpinLock<BTreeMap<u64, Waker>> = IrqSafeSpinLock::new(BTreeMap::new());

/// Install the task runtime's hooks, returning the ones they replace.
/// Without hooks there is nothing to freeze, and [`freeze_processes`]
/// succeeds at once.
pub fn install(hooks: Hooks) -> Option<Hooks> {
    HOOKS.lock().replace(hooks)
}

/// `pm_freezing`: a freeze is in progress. One atomic load, cheap enough
/// for the timer tick.
pub fn freezing() -> bool {
    FREEZING.load(Ordering::Acquire)
}

/// `try_to_freeze` at a freeze point. `true` means `task` is frozen: the
/// caller parks (returns `Pending`, or yields its stackful context) and
/// asks again when woken. `waker` is what [`thaw_processes`] fires.
pub fn try_to_freeze(task: u64, waker: &Waker) -> bool {
    if !freezing() {
        return false;
    }
    FROZEN.lock().insert(task, waker.clone());
    // A thaw that cleared the flag before the insert drained the map
    // without this waker: take the entry back and run on.
    if freezing() {
        return true;
    }
    FROZEN.lock().remove(&task);
    false
}

/// `frozen(p)`: `task` is parked at a freeze point.
pub fn frozen(task: u64) -> bool {
    FROZEN.lock().contains_key(&task)
}

/// One `try_to_freeze_tasks` pass: kick every live task that is not yet
/// frozen, and return them.
fn pass() -> Vec<u64> {
    let Some(hooks) = *HOOKS.lock() else {
        return Vec::new();
    };
    let live = (hooks.live)();
    let todo: Vec<u64> = {
        let frozen = FROZEN.lock();
        live.into_iter()
            .filter(|t| !frozen.contains_key(t))
            .collect()
    };
    for &task in &todo {
        (hooks.kick)(task);
    }
    todo
}

/// `freeze_processes`: freeze every user task, waiting up to
/// [`FREEZE_TIMEOUT_MS`]. On a timeout it thaws them all again.
pub async fn freeze_processes() -> Result<(), FreezeError> {
    freeze_processes_within(FREEZE_TIMEOUT_MS * 1_000_000).await
}

/// [`freeze_processes`] with its timeout in nanoseconds.
pub async fn freeze_processes_within(timeout_ns: u64) -> Result<(), FreezeError> {
    if FREEZING.swap(true, Ordering::AcqRel) {
        return Err(FreezeError::InProgress);
    }
    let start = narf_time::monotonic_ns();
    // `try_to_freeze_tasks`: sleep between passes, 1 ms doubling to 8 ms.
    let mut sleep_us = 1_000;
    loop {
        let todo = pass();
        if todo.is_empty() {
            return Ok(());
        }
        if narf_time::monotonic_ns().saturating_sub(start) >= timeout_ns {
            thaw_processes();
            return Err(FreezeError::Timeout { refusing: todo });
        }
        narf_time::usleep_range(sleep_us / 2, sleep_us).await;
        if sleep_us < 8_000 {
            sleep_us *= 2;
        }
    }
}

/// `thaw_processes`: end the freeze and wake every frozen task.
pub fn thaw_processes() {
    FREEZING.store(false, Ordering::Release);
    let frozen = core::mem::take(&mut *FROZEN.lock());
    for (_, waker) in frozen {
        waker.wake();
    }
}

/// Clear the freezer and its hooks for a test, returning the hooks it had.
#[cfg(feature = "kernel-test")]
#[doc(hidden)]
pub fn __test_reset() -> Option<Hooks> {
    thaw_processes();
    HOOKS.lock().take()
}

/// Put back the hooks [`__test_reset`] returned.
#[cfg(feature = "kernel-test")]
#[doc(hidden)]
pub fn __test_restore(hooks: Option<Hooks>) {
    thaw_processes();
    *HOOKS.lock() = hooks;
}

#[cfg(feature = "kernel-test")]
#[path = "freezer_tests.rs"]
mod tests;
