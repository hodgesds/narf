//! Process-level CPU time: Linux `signal_struct::{utime, stime, cutime,
//! cstime}` and the thread-group sums built from them.
//!
//! Each thread's own `utime`/`stime` is the scheduler's exact per-task
//! accounting ([`narf_scheduler::TaskCputime`], `kernel/sched/cputime.c`
//! vtime). A [`ProcessCputime`] is shared by every thread of a thread group
//! (inherited across `CLONE_THREAD`, fresh for `fork`), as `signal_struct`
//! is, and holds:
//!
//! * the live members, summed on read (`thread_group_cputime`);
//! * the times of members that have been released (`__exit_signal` folds an
//!   exiting thread into `sig->utime/stime`);
//! * the times of reaped children, including what they had collected from
//!   their own reaped children (`wait_task_zombie` folds
//!   `tgutime + sig->cutime` into the parent's `cutime`, likewise `cstime`).
//!
//! Membership changes and reads take the group's lock, so a thread being
//! released is counted exactly once: in the live sum before, in the dead
//! total after.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;
use narf_scheduler::{TaskCputime, TaskTimes};

/// One thread group's CPU-time state (`signal_struct`'s cputime fields).
#[derive(Debug)]
pub(crate) struct ProcessCputime {
    inner: IrqSafeSpinLock<Inner>,
}

impl Default for ProcessCputime {
    fn default() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(Inner::default()),
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    members: Vec<Arc<TaskCputime>>,
    dead: TaskTimes,
    children: TaskTimes,
}

fn add(a: TaskTimes, b: TaskTimes) -> TaskTimes {
    TaskTimes {
        utime_ns: a.utime_ns.saturating_add(b.utime_ns),
        stime_ns: a.stime_ns.saturating_add(b.stime_ns),
    }
}

impl Inner {
    fn group(&self) -> TaskTimes {
        self.members
            .iter()
            .fold(self.dead, |sum, member| add(sum, member.sample()))
    }
}

impl ProcessCputime {
    /// A thread joined the group (fork leader or `CLONE_THREAD` sibling).
    pub(crate) fn join(&self, thread: &Arc<TaskCputime>) {
        let mut inner = self.inner.lock();
        if !inner.members.iter().any(|m| Arc::ptr_eq(m, thread)) {
            inner.members.push(thread.clone());
        }
    }

    /// A thread left the group (released): its times move to the dead
    /// total under the same lock that readers take.
    pub(crate) fn leave(&self, thread: &Arc<TaskCputime>) {
        let mut inner = self.inner.lock();
        if let Some(index) = inner.members.iter().position(|m| Arc::ptr_eq(m, thread)) {
            let gone = inner.members.swap_remove(index);
            inner.dead = add(inner.dead, gone.sample());
        }
    }

    /// `thread_group_cputime`: every member, live or released.
    pub(crate) fn group(&self) -> TaskTimes {
        self.inner.lock().group()
    }

    /// [`Self::group`] for interrupt context: `None` on lock contention.
    pub(crate) fn group_try(&self) -> Option<TaskTimes> {
        self.inner.try_lock().map(|inner| inner.group())
    }

    /// `sig->cutime`/`sig->cstime`: reaped children and their descendants.
    pub(crate) fn children(&self) -> TaskTimes {
        self.inner.lock().children
    }

    /// `RUSAGE_BOTH`: the group plus its reaped children, as `wait4` reports
    /// a reaped child and as the parent's children total absorbs it.
    pub(crate) fn both(&self) -> TaskTimes {
        let inner = self.inner.lock();
        add(inner.group(), inner.children)
    }

    /// Fold a reaped child's `RUSAGE_BOTH` into this group's children.
    pub(crate) fn add_children(&self, child: TaskTimes) {
        let mut inner = self.inner.lock();
        inner.children = add(inner.children, child);
    }

    /// Test hook: forget the reaped-children total.
    #[doc(hidden)]
    pub(crate) fn __test_reset_children(&self) {
        self.inner.lock().children = TaskTimes::default();
    }
}

#[cfg(any(test, feature = "kernel-test"))]
fn group_accounting_is_exact() -> bool {
    let group = Arc::new(ProcessCputime::default());
    let leader = Arc::new(TaskCputime::new());
    let sibling = Arc::new(TaskCputime::new());
    group.join(&leader);
    group.join(&sibling);
    group.join(&sibling);
    leader.__test_charge(30, 10);
    sibling.__test_charge(5, 7);
    let live = group.group();
    if live
        != (TaskTimes {
            utime_ns: 35,
            stime_ns: 17,
        })
    {
        return false;
    }
    // A released thread keeps counting, exactly once.
    group.leave(&sibling);
    group.leave(&sibling);
    sibling.__test_charge(1_000, 1_000);
    if group.group() != live {
        return false;
    }
    // Children fold into `both` but never into the group itself.
    group.add_children(TaskTimes {
        utime_ns: 100,
        stime_ns: 200,
    });
    group.group() == live
        && group.children()
            == TaskTimes {
                utime_ns: 100,
                stime_ns: 200,
            }
        && group.both()
            == TaskTimes {
                utime_ns: 135,
                stime_ns: 217,
            }
}

#[cfg(test)]
#[test]
fn group_accounting_counts_members_dead_and_children_once() {
    assert!(group_accounting_is_exact());
}

#[cfg(feature = "kernel-test")]
fn smoke_process_cputime_group_accounting() -> narf_kernel_test::TestResult {
    if group_accounting_is_exact() {
        narf_kernel_test::TestResult::Pass
    } else {
        narf_kernel_test::TestResult::Fail("thread-group CPU time lost or double-counted a thread")
    }
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "syscall_abi/proc_snapshot",
    smoke_process_cputime_group_accounting
);
