#[allow(unused_imports)]
use super::*;

/// `rt_sigqueueinfo(pid, sig, info)` — queue `sig` and its `siginfo_t`
/// payload to `pid` for signal delivery, sigtimedwait, or signalfd.
///
/// `pid` is interpreted in the CALLER's PID namespace, exactly like
/// `kill(2)`: Linux `kernel/signal.c` routes `do_rt_sigqueueinfo` →
/// `kill_proc_info` → `find_task_by_vpid`, i.e. a *virtual* pid lookup in
/// the caller's namespace. Delivery here is keyed on the OUTER pid, so the
/// argument must be translated first (see `sys_kill`).
///
/// Why this is load-bearing: systemd runs under `unshare --pid`, and its
/// udevd manager acks every worker's INOTIFY_WATCH_ADD/REMOVE notification
/// with `sigqueue(inner_pid, SIGUSR1)` — the PidRef carries no pidfd
/// (NARF attaches no SCM_PIDFD), so it lands here. Untranslated, the inner
/// pid is used as an outer pid and the signal goes to whatever process owns
/// that number in the OUTER pid space — and small numbers are ALWAYS owned
/// (early boot processes). The call still returns 0, so nothing is logged
/// anywhere: the manager believes it acked, the worker waits forever for an
/// ack that went to a stranger, never goes idle, is never reused, and the
/// manager forks fresh workers up to the `children_max=18` ceiling.
pub(crate) fn sys_rt_sigqueueinfo(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    // Linux copies siginfo before validating the target or signal. In
    // particular NULL/unreadable uinfo wins with EFAULT over EINVAL/ESRCH.
    let info = match import_queued_siginfo(a.arg2) {
        Ok(info) => info,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let user_pid = a.arg0 as i32;
    let sig = a.arg1 as u32;
    // Users may supply SI_QUEUE and the other negative user-origin codes, but
    // may not impersonate the kernel or tkill when targeting another task.
    if siginfo_requires_self_target(info)
        && user_pid != linux_tid_for_task(current_task_id()) as i32
    {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }
    let pid = if user_pid > 0 {
        accept_pid_from(current_task_id(), user_pid as u64)
    } else {
        None
    };
    let Some(pid) = pid else {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
        return;
    };
    let target = pid_to_task_raw(pid).unwrap_or(pid);
    // ESRCH for a vanished target (Linux rt_sigqueueinfo(2)).
    if !signal_target_exists(target) {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64));
        return;
    }
    // kill_pid_info reaches signal validation only after resolving a live
    // target, so a missing target wins over an invalid signum.
    if sig > 64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // Signal 0 is an existence/permission probe; imported siginfo is not queued.
    if sig == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Store the payload and set the pending bit atomically (bucket lock across
    // both), so a sigwait consumer can't pop the coalesced payload between the
    // store and the raise and strand the bit → spurious SI_USER sival=0.
    let depth = match sigqueue_deliver_imported(target, sig, info) {
        Some(d) => d,
        None => {
            // Target's queued-signal budget exhausted (RLIMIT_SIGPENDING
            // analogue): deliver nothing, tell the sender to back off.
            ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN
            return;
        }
    };
    // Producer/consumer back-pressure: the target is falling behind — yield
    // this sender at syscall exit so the consumer(s) drain (see
    // SIGQUEUE_BACKPRESSURE_DEPTH). `depth` is the post-enqueue queue depth
    // returned by the atomic deliver, so no second scan/lock.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if depth > SIGQUEUE_BACKPRESSURE_DEPTH {
        narf_scheduler::stackful::request_syscall_backpressure_yield();
    }
    ctx.set_return(SyscallReturn::ok(0));
}
