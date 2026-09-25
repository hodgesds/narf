#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE1(sched_getscheduler, pid_t, pid)`.
///
/// ```text
/// if (pid < 0)
///         return -EINVAL;
/// p = find_process_by_pid(pid);
/// if (!p)
///         return -ESRCH;
/// retval = p->policy;
/// if (p->sched_reset_on_fork)
///         retval |= SCHED_RESET_ON_FORK;
/// return retval;
/// ```
///
/// This used to return SCHED_OTHER for every argument — including a
/// negative pid and a pid naming no task, which Linux refuses — and so
/// could never reflect a `sched_setscheduler` that had just succeeded.
pub(crate) fn sys_sched_getscheduler(ctx: &mut dyn TrapContext) {
    // `pid_t` is `int` — the low 32 bits, sign-extended.
    let pid = ctx.args().arg0 as i32;
    if pid < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let Some(task) = find_process_by_pid(pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    let st = read_sched_state(task);
    let word = st.policy | if st.reset_on_fork { SCHED_RESET_ON_FORK } else { 0 };
    ctx.set_return(SyscallReturn::ok(word as u64));
}
