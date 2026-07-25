#[allow(unused_imports)]
use super::*;

/// Linux tgkill(2): like kill but with an explicit (tgid, tid)
/// pair. NARF is single-threaded per process — we forward tid as
/// the kill target and ignore tgid (the disambiguation it provides
/// will matter once threading lands).
pub(crate) fn sys_tgkill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tgid = args.arg0;
    let tid = args.arg1;
    let signum = args.arg2 as u32;
    let esrch = SyscallReturn::ok((-3i64) as u64);
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
    if tgid != 0 && task_to_pid_raw(tid).unwrap_or(tid) != tgid {
        ctx.set_return(esrch);
        return;
    }
    // Null signal: existence/permission probe only — queue nothing (see sys_kill).
    if signum == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    signal_stopcont_interaction(tid, signum);
    raise_signal_pending(tid, signum);
    wake_signal(tid);
    ctx.set_return(SyscallReturn::ok(0));
}
