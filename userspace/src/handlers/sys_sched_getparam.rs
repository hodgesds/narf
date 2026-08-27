#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE2(sched_getparam, pid_t, pid,
/// struct sched_param __user *, param)`.
///
/// ```text
/// if (unlikely(!param || pid < 0))
///         return -EINVAL;
/// p = find_process_by_pid(pid);
/// if (!p)
///         return -ESRCH;
/// ...
/// return copy_to_user(param, &lp, sizeof(*param)) ? -EFAULT : 0;
/// ```
///
/// The check ORDER is load-bearing: a null `param` is -EINVAL even when
/// `pid` also names no task, so a caller cannot mistake its own null
/// pointer for "that process went away". Both of those arms, plus the
/// trailing copy fault, previously returned a bare -1 → EPERM.
pub(crate) fn sys_sched_getparam(ctx: &mut dyn TrapContext) {
    const ESRCH: i64 = 3;
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    let args = *ctx.args();
    // `pid_t` is `int` — the argument is the low 32 bits, sign-extended.
    let pid = args.arg0 as i32;
    let out = args.arg1;
    if out == 0 || pid < 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // `pid` is resolved in the CALLER's pid namespace (Linux
    // kernel/sched/syscalls.c), like sys_sched_getaffinity. Translate
    // inner -> outer -> TaskId before keying the sched-param table. Audit
    // finding #18.
    let caller = current_task_id();
    let task = if pid == 0 {
        caller
    } else {
        let Some(outer) = accept_pid_from(caller, pid as u64) else {
            ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
            return;
        };
        let resolved = proc_pid_to_tid(outer);
        // `find_process_by_pid(pid)` returns NULL for a pid that names no
        // task, and Linux reports -ESRCH. `proc_pid_to_tid` falls back to the
        // identity mapping for an unregistered pid, so without this check the
        // handler read an ABSENT SCHED_PARAM_TABLE row and reported the
        // `unwrap_or(0)` default — telling the caller that a process which
        // does not exist has priority 0, which is indistinguishable from a
        // real process that does. The caller always resolves, even in
        // syscall-unit fixtures that never populate the task registry.
        if resolved != caller && crate::task::task_get(resolved).is_none() {
            ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
            return;
        }
        resolved
    };
    let g = SCHED_PARAM_TABLE.lock();
    let val = g.as_ref().and_then(|m| m.get(&task).copied()).unwrap_or(0);
    drop(g);
    // Write one i32 to user space under the SMAP bracket.
    // SAFETY: `out` is the user sched_param pointer (non-zero, checked above);
    // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
    if unsafe { copy_to_user(out, &val.to_ne_bytes()) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
