#[allow(unused_imports)]
use super::*;

/// Linux tgkill(2): like kill but with an explicit (tgid, tid)
/// pair. NARF is single-threaded per process — we forward tid as
/// the kill target and ignore tgid (the disambiguation it provides
/// will matter once threading lands).
pub(crate) fn sys_tgkill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tgid = args.arg0;
    let esrch = SyscallReturn::ok((-3i64) as u64);
    let tid = match signal_tid_from_user(current_task_id(), args.arg1) {
        Some(tid) => tid,
        None => {
            ctx.set_return(esrch);
            return;
        }
    };
    let signum = args.arg2 as u32;
    if signum > 64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // ESRCH for a dead/never-existed tid — no more phantom pending
    // bits on arbitrary numeric keys.
    if !signal_target_exists(tid) {
        ctx.set_return(esrch);
        return;
    }
    // The (tgid, tid) consistency check is tgkill's whole point over
    // tkill: it prevents a recycled tid in ANOTHER process from
    // absorbing the signal. Our tids never recycle, but the check is
    // still Linux-visible semantics (musl relies on ESRCH here).
    let outer_tgid = if tgid == 0 {
        0
    } else {
        match accept_pid_from(current_task_id(), tgid) {
            Some(tgid) => tgid,
            None => {
                ctx.set_return(esrch);
                return;
            }
        }
    };
    if outer_tgid != 0 && task_to_pid_raw(tid).unwrap_or(tid) != outer_tgid {
        ctx.set_return(esrch);
        return;
    }
    // Null signal: existence/permission probe only — queue nothing (see sys_kill).
    if signum == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    queue_sender_siginfo(tid, signum);
    signal_stopcont_interaction(tid, signum);
    raise_signal_pending(tid, signum);
    wake_signal(tid);
    ctx.set_return(SyscallReturn::ok(0));
}
