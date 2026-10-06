#[allow(unused_imports)]
use super::*;

/// `kernel/signal.c::SYSCALL_DEFINE2(tkill, pid_t, pid, int, sig)`:
///
/// ```text
/// if (pid <= 0) return -EINVAL;
/// return do_tkill(0, pid, sig);
///     p = find_task_by_vpid(pid);          // any thread → else -ESRCH
///     check_kill_permission(sig, info, p); // !valid_signal → -EINVAL
///     if (sig) do_send_sig_info(sig, info, p, PIDTYPE_PID);
/// ```
///
/// The target lookup precedes the signal-number check, so a missing thread is
/// -ESRCH even with an invalid signal.
pub(crate) fn sys_tkill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0 as i32;
    let signum = args.arg1 as u32;
    if pid <= 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let Some(tid) = find_task_by_vpid(current_task_id(), pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    if signum > 64 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    if signum == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    raise_tkill_signal_pending(tid, signum);
    ctx.set_return(SyscallReturn::ok(0));
}
