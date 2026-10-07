#[allow(unused_imports)]
use super::*;

/// `kernel/fork.c::SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr)`:
///
/// ```text
/// current->clear_child_tid = tidptr;
/// return task_pid_vnr(current);
/// ```
///
/// The return value is the caller's TID in its own PID namespace — the number
/// `gettid()` reports — not NARF's internal scheduler TaskId, which differs
/// after a fork. glibc stores it as the main thread's `pd->tid` and passes it
/// to `sched_getparam`, `sched_getscheduler`, `tgkill` and the owner field of
/// PI and robust mutexes, so a wrong number there silently retargets all of
/// them.
pub(crate) fn sys_set_tid_address(ctx: &mut dyn TrapContext) {
    let tidptr = ctx.args().arg0;
    let me = current_task_id();
    // Recorded regardless of value; 0 disables clear_child_tid.
    set_clear_child_tid(me, tidptr);
    ctx.set_return(SyscallReturn::ok(linux_tid_for_task(me)));
}
