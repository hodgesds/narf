#[allow(unused_imports)]
use super::*;

/// `rt_sigqueueinfo(pid, sig, info)` — queue `sig` to `pid`. NARF's
/// pending-signal model is a per-task bitmask, so the accompanying
/// `siginfo_t` payload isn't preserved, but the signal is delivered
/// exactly like `kill(2)`/`tkill(2)`.
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
    let sig = a.arg1 as u32;
    if sig > 64 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    #[allow(unused_mut)]
    let mut pid = a.arg0;
    #[cfg(feature = "container")]
    {
        match crate::pid_ns::resolve_inner_pid(current_task_id(), pid) {
            Some(outer) => pid = outer,
            None => {
                // Not bound in the caller's namespace → ESRCH, never a
                // same-numbered process from another namespace.
                ctx.set_return(SyscallReturn::ok((-3i64) as u64));
                return;
            }
        }
    }
    let target = pid_to_task_raw(pid).unwrap_or(pid);
    // ESRCH for a vanished target (Linux rt_sigqueueinfo(2)).
    if !signal_target_exists(target) {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64));
        return;
    }
    let depth = match capture_queued_siginfo(target, sig, a.arg2) {
        Some(d) => d,
        None => {
            // Target's queued-signal budget exhausted (RLIMIT_SIGPENDING
            // analogue): deliver nothing, tell the sender to back off.
            ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN
            return;
        }
    };
    raise_signal_pending(target, sig); // ORs the pending bit + wakes
                                       // Producer/consumer back-pressure: the target is falling behind —
                                       // yield this sender at syscall exit so the consumer(s) drain (see
                                       // SIGQUEUE_BACKPRESSURE_DEPTH). `depth` is the post-enqueue queue
                                       // depth returned by capture_queued_siginfo, so no second scan/lock.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if depth > SIGQUEUE_BACKPRESSURE_DEPTH {
        narf_scheduler::stackful::request_syscall_backpressure_yield();
    }
    ctx.set_return(SyscallReturn::ok(0));
}
