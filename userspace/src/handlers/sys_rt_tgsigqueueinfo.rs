#[allow(unused_imports)]
use super::*;

/// `rt_tgsigqueueinfo(tgid, tid, sig, info)` — queue `sig` to thread
/// `tid`. Same pending-bitmask delivery as `rt_sigqueueinfo`.
///
/// Both `tgid` and `tid` are CALLER-namespace pids, exactly like
/// `tgkill(2)`: Linux `kernel/signal.c` `do_rt_tgsigqueueinfo` resolves
/// them via `find_task_by_vpid`, a virtual lookup in the caller's pid
/// namespace. NARF keys delivery on the OUTER pid, so both arguments are
/// translated before use — including the tgid the consistency check
/// compares against, so both sides of that comparison live in outer space.
///
/// Why this is load-bearing: see `sys_rt_sigqueueinfo`. systemd runs under
/// `unshare --pid`; its udevd manager acks each worker's INOTIFY_WATCH_*
/// notification with `sigqueue(inner_pid, SIGUSR1)`. Untranslated, the ack
/// is delivered to whatever process owns that number in the OUTER pid
/// space, the call still returns 0 so nothing is logged, the worker waits
/// forever for its ack, never goes idle, is never reused, and the manager
/// forks fresh workers to the `children_max=18` ceiling.
pub(crate) fn sys_rt_tgsigqueueinfo(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let sig = a.arg2 as u32;
    if sig > 64 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    #[allow(unused_mut)]
    let (mut tgid, mut tid) = (a.arg0, a.arg1);
    #[cfg(feature = "container")]
    {
        let caller = current_task_id();
        // A tgid of 0 is the "don't check" wildcard below — leave it alone.
        if tgid != 0 {
            match crate::pid_ns::resolve_inner_pid(caller, tgid) {
                Some(outer) => tgid = outer,
                None => {
                    ctx.set_return(SyscallReturn::ok((-3i64) as u64));
                    return;
                }
            }
        }
        match crate::pid_ns::resolve_inner_pid(caller, tid) {
            Some(outer) => tid = outer,
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64));
                return;
            }
        }
    }
    let target = pid_to_task_raw(tid).unwrap_or(tid);
    // ESRCH for a vanished target + tgid consistency (see sys_tgkill).
    if !signal_target_exists(target)
        || (tgid != 0 && task_to_pid_raw(target).unwrap_or(target) != tgid)
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
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if sigqueue_depth(target) > SIGQUEUE_BACKPRESSURE_DEPTH {
        narf_scheduler::stackful::request_syscall_backpressure_yield();
    }
    ctx.set_return(SyscallReturn::ok(0));
}
