#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE2(sched_setparam, pid_t, pid,
/// struct sched_param __user *, param)` →
/// `do_sched_setscheduler(pid, SETPARAM_POLICY, param)`, which keeps the
/// task's existing policy and sets only `sched_priority`.
///
/// ```text
/// if (!param || pid < 0)                       return -EINVAL;
/// if (copy_from_user(&lparam, param, ...))     return -EFAULT;
/// p = find_process_by_pid(pid);
/// if (!p)                                      return -ESRCH;
/// /* __sched_setscheduler: */
/// if (attr->sched_priority > MAX_RT_PRIO-1)    return -EINVAL;
/// if (rt_policy(policy) != (attr->sched_priority != 0))
///                                              return -EINVAL;
/// if (user) retval = user_check_sched_setscheduler(...);   /* -EPERM */
/// ```
///
/// The priority rule is judged against the task's CURRENT policy: 0 is the
/// only value a SCHED_OTHER/BATCH/IDLE task accepts, and 1..=99 the only
/// values a SCHED_FIFO/RR one does. Raising an RT priority past the
/// target's RLIMIT_RTPRIO, or touching another user's task, needs
/// CAP_SYS_NICE (`user_check_sched_setscheduler`).
pub(crate) fn sys_sched_setparam(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `pid_t` is `int`; reading the whole register let a negative pid
    // arrive as a huge positive value and miss the `pid < 0` guard.
    let pid = args.arg0 as i32;
    match do_sched_setscheduler(pid, SETPARAM_POLICY, args.arg1) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(e) => ctx.set_return(errno_ret(e)),
    }
}
