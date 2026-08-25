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
    let info = match import_queued_siginfo(a.arg3) {
        Ok(info) => info,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let user_tgid = a.arg0 as i32;
    let user_tid = a.arg1 as i32;
    // Linux rejects both zero and negative identifiers after importing uinfo.
    if user_tgid <= 0 || user_tid <= 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if siginfo_requires_self_target(info)
        && user_tid != linux_tid_for_task(current_task_id()) as i32
    {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }
    let sig = a.arg2 as u32;
    let caller = current_task_id();
    let Some(tgid) = accept_pid_from(caller, user_tgid as u64) else {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64));
        return;
    };
    let Some(target) = signal_tid_from_user(caller, user_tid as u64) else {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64));
        return;
    };
    // ESRCH for a vanished target + tgid consistency (see sys_tgkill).
    if !signal_target_exists(target) || task_to_pid_raw(target).unwrap_or(target) != tgid {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64));
        return;
    }
    if sig > 64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if sig == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let depth = match enqueue_imported_siginfo(target, sig, info) {
        Some(d) => d,
        None => {
            ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN (see rt_sigqueueinfo)
            return;
        }
    };
    raise_signal_pending(target, sig);
    // Back-pressure — see sys_rt_sigqueueinfo. `depth` comes from the enqueue,
    // so there is no second sigqueue-bucket lock/scan on this send path.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if depth > SIGQUEUE_BACKPRESSURE_DEPTH {
        narf_scheduler::stackful::request_syscall_backpressure_yield();
    }
    ctx.set_return(SyscallReturn::ok(0));
}
