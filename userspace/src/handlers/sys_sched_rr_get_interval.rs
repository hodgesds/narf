#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE2(sched_rr_get_interval, pid_t,
/// pid, struct __kernel_timespec __user *, interval)`.
///
/// ```text
/// static int sched_rr_get_interval(pid_t pid, struct timespec64 *t)
/// {
///         if (pid < 0)                            return -EINVAL;
///         struct task_struct *p = find_process_by_pid(pid);
///         if (!p)                                 return -ESRCH;
///         ...
/// }
/// /* then */
/// if (retval == 0)
///         retval = put_timespec64(&t, interval);   /* -EFAULT */
/// ```
///
/// `pid` was read and discarded. The cooperative policy has no round-robin
/// quantum, so the VALUE reported is `{0, 0}` either way — but that is not
/// a licence to skip resolving the argument, because the value is not the
/// only thing the call communicates. `sched_rr_get_interval(-1, buf)` and
/// `sched_rr_get_interval(<dead pid>, buf)` are how a caller discovers that
/// its argument is wrong or its target has exited; answering 0 to both
/// tells it the process is alive and running with no quantum.
///
/// The destination is written only after the pid resolves, per the
/// `if (retval == 0)` guard above.
pub(crate) fn sys_sched_rr_get_interval(ctx: &mut dyn TrapContext) {
    const ESRCH: i64 = 3;
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    let args = *ctx.args();
    // `pid_t` is `int` — the argument is the low 32 bits, sign-extended.
    let pid = args.arg0 as i32;
    let buf = args.arg1;
    if pid < 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // `find_process_by_pid(pid)` resolves in the CALLER's pid namespace;
    // pid == 0 is the caller itself and always exists.
    let caller = current_task_id();
    if pid != 0 {
        let Some(outer) = accept_pid_from(caller, pid as u64) else {
            ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
            return;
        };
        let resolved = proc_pid_to_tid(outer);
        // `proc_pid_to_tid` falls back to the identity mapping for an
        // unregistered pid, so an existence check is what actually
        // implements `if (!p) return -ESRCH;`.
        if resolved != caller && crate::task::task_get(resolved).is_none() {
            ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
            return;
        }
    }
    // `put_timespec64(&t, interval)` — only reached once the pid resolved.
    // A NULL destination fails range validation here, which is Linux's
    // path: there is no separate null check.
    let kbuf = [0u8; 16]; // tv_sec = 0, tv_nsec = 0
    // SAFETY: copy_to_user range-validates `buf` (including the null case)
    // and SMAP-brackets the 16-byte write.
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
