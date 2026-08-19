#[allow(unused_imports)]
use super::*;

/// `tkill(tid, sig)` — thread-targeted signal delivery. NARF is
/// single-thread-per-process until clone3 lands, so tkill is a
/// thin wrapper over the same SIGNAL_PENDING table that `kill`
/// uses, addressed by tid instead of pid.
pub(crate) fn sys_tkill(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tid = match signal_tid_from_user(current_task_id(), args.arg0) {
        Some(tid) => tid,
        None => {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64));
            return;
        }
    };
    let signum = args.arg1 as u32;
    if signum > 64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // ESRCH for a dead/never-existed tid (Linux tkill(2)).
    if !signal_target_exists(tid) {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64));
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
