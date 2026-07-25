#[allow(unused_imports)]
use super::*;

/// `rt_sigqueueinfo(pid, sig, info)` — queue `sig` to `pid`. NARF's
/// pending-signal model is a per-task bitmask, so the accompanying
/// `siginfo_t` payload isn't preserved, but the signal is delivered
/// exactly like `kill(2)`/`tkill(2)`.
pub(crate) fn sys_rt_sigqueueinfo(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let sig = a.arg1 as u32;
    if sig > 64 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let target = pid_to_task_raw(a.arg0).unwrap_or(a.arg0);
    // ESRCH for a vanished target (Linux rt_sigqueueinfo(2)).
    if !signal_target_exists(target) {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64));
        return;
    }
    if !capture_queued_siginfo(target, sig, a.arg2) {
        // Target's queued-signal budget exhausted (RLIMIT_SIGPENDING
        // analogue): deliver nothing, tell the sender to back off.
        ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN
        return;
    }
    raise_signal_pending(target, sig); // ORs the pending bit + wakes
                                       // Producer/consumer back-pressure: the target is falling behind —
                                       // yield this sender at syscall exit so the consumer(s) drain (see
                                       // SIGQUEUE_BACKPRESSURE_DEPTH).
    #[cfg(target_arch = "x86_64")]
    if sigqueue_depth(target) > SIGQUEUE_BACKPRESSURE_DEPTH {
        narf_scheduler::stackful::request_syscall_backpressure_yield();
    }
    ctx.set_return(SyscallReturn::ok(0));
}
