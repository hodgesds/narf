#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE3(sched_setscheduler, pid_t, pid,
/// int, policy, struct sched_param __user *, param)`.
///
/// ```text
/// if (policy < 0)
///         return -EINVAL;
/// return do_sched_setscheduler(pid, policy, param);
/// ```
///
/// This used to validate the policy number and return 0 without reading
/// `param` at all — so a NULL param succeeded, `SCHED_FIFO` at priority 0
/// (which Linux refuses) succeeded, an unprivileged task could become
/// real-time, and `sched_getscheduler` still said SCHED_OTHER afterwards.
/// The whole of `__sched_setscheduler` now runs, in Linux's order, in
/// [`sched_setscheduler_checked`].
pub(crate) fn sys_sched_setscheduler(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `pid_t` and `int` — the low 32 bits of each register.
    let pid = args.arg0 as i32;
    let policy = args.arg1 as i32;
    if policy < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    match do_sched_setscheduler(pid, policy, args.arg2) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(e) => ctx.set_return(errno_ret(e)),
    }
}
