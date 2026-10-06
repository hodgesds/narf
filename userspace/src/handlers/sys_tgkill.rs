#[allow(unused_imports)]
use super::*;

/// `kernel/signal.c::SYSCALL_DEFINE3(tgkill, pid_t, tgid, pid_t, pid, int, sig)`:
///
/// ```text
/// if (pid <= 0 || tgid <= 0) return -EINVAL;
/// do_send_specific(tgid, pid, sig, info):
///     p = find_task_by_vpid(pid);                        // any thread
///     if (p && task_tgid_vnr(p) == tgid)                 // else -ESRCH
///         check_kill_permission(sig, info, p);           // -EINVAL bad sig
///         if (sig) do_send_sig_info(sig, info, p, PIDTYPE_PID);
/// ```
///
/// Both ids are in the caller's pid namespace; the tgid check is what makes
/// tgkill safe against tid reuse, so a thread that is not (or no longer) in
/// `tgid` is -ESRCH.
pub(crate) fn sys_tgkill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tgid = args.arg0 as i32;
    let pid = args.arg1 as i32;
    let signum = args.arg2 as u32;
    if pid <= 0 || tgid <= 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let caller = current_task_id();
    let Some(tid) = find_task_by_vpid(caller, pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    // `task_tgid_vnr(p) == tgid`: compare in the outer number space.
    let in_group = accept_pid_from(caller, tgid as u64)
        .is_some_and(|outer_tgid| task_to_pid_raw(tid).unwrap_or(tid) == outer_tgid);
    if !in_group {
        ctx.set_return(errno_ret(ESRCH));
        return;
    }
    if signum > 64 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // Null signal: existence/permission probe only — queue nothing.
    if signum == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    raise_tkill_signal_pending(tid, signum);
    ctx.set_return(SyscallReturn::ok(0));
}
