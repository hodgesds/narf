#[allow(unused_imports)]
use super::*;

/// `rt_tgsigqueueinfo(tgid, tid, sig, info)` — queue `sig` to thread
/// `tid`. Same pending-bitmask delivery as `rt_sigqueueinfo`.
pub(crate) fn sys_rt_tgsigqueueinfo(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let sig = a.arg2 as u32;
    if sig > 64 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let target = pid_to_task_raw(a.arg1).unwrap_or(a.arg1);
    // ESRCH for a vanished target + tgid consistency (see sys_tgkill).
    if !signal_target_exists(target)
        || (a.arg0 != 0 && task_to_pid_raw(target).unwrap_or(target) != a.arg0)
    {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64));
        return;
    }
    if !capture_queued_siginfo(target, sig, a.arg3) {
        ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN (see rt_sigqueueinfo)
        return;
    }
    raise_signal_pending(target, sig);
    // Back-pressure — see sys_rt_sigqueueinfo.
    #[cfg(target_arch = "x86_64")]
    if sigqueue_depth(target) > SIGQUEUE_BACKPRESSURE_DEPTH {
        narf_scheduler::stackful::request_syscall_backpressure_yield();
    }
    ctx.set_return(SyscallReturn::ok(0));
}
