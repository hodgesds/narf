//! Refcounted task lifetime — NARF's `task_struct`.
//!
//! Linux mapping: `Arc<Task>` ≙ `task_struct` + its refcount
//! (`get_task_struct`/`put_task_struct` ≙ `Arc::clone`/drop);
//! [`TASKS`] ≙ the pid table (holds one ref while the task is
//! findable); [`release_task`] ≙ `release_task()`.
//!
//! Lifetime rules (see `docs/TASK_LIFETIME_REDESIGN.md`):
//!
//! 1. `TASKS` holds exactly one `Arc` from spawn registration until
//!    the task is reaped ([`release_task`]). Any holder that needs the
//!    task beyond a lock section clones the `Arc` — dereferencing NEVER
//!    requires holding the registry lock. This replaces the old
//!    `USER_TASK_CTXS` raw-`*mut UserTaskCtx` registry whose safety
//!    hung on a deref-under-lock convention.
//! 2. The task's `UserTaskFuture` holds an `Arc<Task>` for its whole
//!    life, so the executor dropping the slot is a ref-put, not a free
//!    — and the `UserTaskCtx` address stays stable (and valid) for
//!    every raw self-pointer the in-flight trap/syscall paths hold.
//! 3. Exit marks the task [`TASK_ZOMBIE`] (it stays findable, carrying
//!    its exit code, until the parent reaps). Reaping removes the
//!    registry ref; the memory is freed when the LAST `Arc` drops.
//! 4. IRQ contexts must never drop an `Arc<Task>` (NARF forbids
//!    allocator frees in IRQ context — the `deferred_wake` rule). IRQ
//!    paths keep operating on tids + `Arc<WakeCell>` wakers only.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::user_task::UserTaskCtx;

/// Task is live (running or parked).
pub const TASK_RUNNING: u32 = 0;
/// Task has executed its exit path; only the reap-visible husk
/// (exit code, identity) is meaningful. Still present in [`TASKS`].
pub const TASK_ZOMBIE: u32 = 2;

/// The kernel-side task object. One per user task, shared by `Arc`.
pub struct Task {
    /// Scheduler `TaskId.raw()` — monotonic, NEVER reused. This
    /// monotonicity is the ABA-safety anchor for every tid-keyed
    /// table; do not introduce tid recycling.
    pub tid: u64,
    /// POSIX pid (thread-group id). PIDs ARE reused (lowest-free
    /// pool), so pid-keyed state must be cleaned at reap.
    pub pid: AtomicU64,
    /// [`TASK_RUNNING`] | [`TASK_ZOMBIE`].
    pub state: AtomicU32,
    /// Raw wstatus staged at exit (also mirrored in the pending-
    /// termination table until the reap plumbing migrates here).
    pub exit_code: AtomicI32,
    /// Set by `exit_group(2)` (Linux `signal->group_exit`): the whole
    /// thread group is terminating. Consulted so a sibling that races
    /// the group exit reports the group's status.
    pub group_exiting: core::sync::atomic::AtomicBool,
    /// Per-task user context: saved `UserState`, park/wait flags,
    /// futex/epoll generations. Owned HERE (not by the future) so its
    /// address is valid for as long as ANY `Arc<Task>` lives.
    pub uctx: UserTaskCtx,
}

impl Task {
    /// Create and register a task under `tid`. The caller must have
    /// reserved `tid` via `narf_scheduler::alloc_task_id()` and must
    /// register BEFORE the task is enqueued, so the task can resolve
    /// itself from its very first syscall.
    pub fn new_registered(tid: u64, pid: u64) -> Arc<Task> {
        let t = Arc::new(Task {
            tid,
            pid: AtomicU64::new(pid),
            state: AtomicU32::new(TASK_RUNNING),
            exit_code: AtomicI32::new(0),
            group_exiting: core::sync::atomic::AtomicBool::new(false),
            uctx: UserTaskCtx::new(),
        });
        TASKS.lock().insert(tid, t.clone());
        // /proc/[pid]/stat starttime source — every task (spawn, fork,
        // clone, the abi-test harness) registers exactly once, so this
        // is THE creation timestamp. Swept with the other per-task
        // tables at exit.
        crate::handlers::record_task_start_ns(tid);
        t
    }
}

impl core::fmt::Debug for Task {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Task")
            .field("tid", &self.tid)
            .field("pid", &self.pid.load(Ordering::Relaxed))
            .field("state", &self.state.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

/// The task registry — NARF's pid table. Holds ONE `Arc` per task
/// from spawn to reap.
static TASKS: IrqSafeSpinLock<BTreeMap<u64, Arc<Task>>> = IrqSafeSpinLock::new(BTreeMap::new());

/// `get_task_struct`: resolve a tid to a live (or zombie) task,
/// taking a reference. Safe to dereference after the registry lock is
/// released — that is the whole point.
pub fn task_get(tid: u64) -> Option<Arc<Task>> {
    TASKS.lock().get(&tid).cloned()
}

/// The task currently executing on this CPU, if the scheduler has one
/// published. `None` in kernel-test harness contexts.
pub fn current_task() -> Option<Arc<Task>> {
    let tid = crate::handlers::current_task_id();
    if tid == 0 {
        return None;
    }
    task_get(tid)
}

/// Flip a task to ZOMBIE at the top of its exit path. Idempotent;
/// returns `false` if the task was unknown (kernel-test contexts).
pub fn mark_zombie(tid: u64) -> bool {
    match task_get(tid) {
        Some(t) => {
            t.state.store(TASK_ZOMBIE, Ordering::Release);
            true
        }
        None => false,
    }
}

/// `release_task()`: drop the registry's reference at reap time. The
/// memory is freed when the last outstanding `Arc` drops (typically
/// the executor slot's future, if it hasn't been dropped already).
/// Returns the removed task so callers can log/inspect.
pub fn release_task(tid: u64) -> Option<Arc<Task>> {
    TASKS.lock().remove(&tid)
}

/// Number of registered (live + zombie) tasks. Diagnostics only.
pub fn task_count() -> usize {
    TASKS.lock().len()
}

/// Scheduler slot-reap hook (installed at boot via
/// `narf_scheduler::set_slot_reap_hook`). Fires when the executor
/// drops a task slot through an ABNORMAL path — budget-cap revocation
/// or `ChargeOutcome::Kill` — where the task never got to run its own
/// exit sequence. Without this the task would stay RUNNING in the
/// registry forever and its exit observers (fd teardown, SIGCHLD,
/// parent wake) would never fire: the pre-refcount version of this
/// bug left a dangling `*mut UserTaskCtx` behind for `wake_signal`/
/// `wake_one` to dereference.
///
/// Runs in executor (non-IRQ) context, so taking locks and dropping
/// Arcs here is sound.
pub fn slot_reap_handler(id: narf_scheduler::TaskId) {
    let tid = id.raw();
    let Some(t) = task_get(tid) else {
        // Kernel-only task (never registered) — nothing to tear down.
        return;
    };
    if t.state.swap(TASK_ZOMBIE, Ordering::AcqRel) == TASK_ZOMBIE {
        // Already ran its own exit path; the slot drop is the normal
        // post-exit cleanup.
        return;
    }
    let pid = t.pid.load(Ordering::Acquire);
    // The task died without a wstatus: report it as SIGKILL'd, then
    // fan out the same exit-observer sequence `terminate_current_task`
    // would have run (fd teardown, pending-exit staging, parent wake).
    crate::handlers::stage_killed_termination(pid);
    crate::user_task::notify_task_exited(pid, tid);
}

/// Test-only: clear the registry between kernel-test cases.
#[doc(hidden)]
pub fn __test_reset_tasks() {
    TASKS.lock().clear();
}
