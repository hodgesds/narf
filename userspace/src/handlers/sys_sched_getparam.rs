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
/// if (task_has_rt_policy(p))
///         lp.sched_priority = p->rt_priority;
/// return copy_to_user(param, &lp, sizeof(*param)) ? -EFAULT : 0;
/// ```
///
/// The check ORDER is load-bearing: a null `param` is -EINVAL even when
/// `pid` also names no task, so a caller cannot mistake its own null
/// pointer for "that process went away". The reported priority is the RT
/// one or 0 — a SCHED_DEADLINE task reports 0 too, like Linux.
pub(crate) fn sys_sched_getparam(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `pid_t` is `int` — the argument is the low 32 bits, sign-extended.
    let pid = args.arg0 as i32;
    let out = args.arg1;
    if out == 0 || pid < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // Resolved in the CALLER's pid namespace (audit finding #18).
    let Some(task) = find_process_by_pid(pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    let st = read_sched_state(task);
    let val: i32 = if rt_policy(st.policy) {
        st.rt_priority as i32
    } else {
        0
    };
    // SAFETY: `out` is the user sched_param pointer (non-zero, checked above);
    // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
    if unsafe { copy_to_user(out, &val.to_ne_bytes()) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
