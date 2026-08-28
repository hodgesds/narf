#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::sched_setparam(pid, param)` →
/// `do_sched_setscheduler(pid, SETPARAM_POLICY, param)`, which keeps the
/// task's existing policy and sets only `sched_priority`.
///
/// ```text
/// if (!param || pid < 0)                       return -EINVAL;
/// if (copy_from_user(&lparam, param, ...))     return -EFAULT;
/// p = find_process_by_pid(pid);
/// if (!p)                                      return -ESRCH;
/// ...
/// /* __sched_setscheduler: */
/// if (attr->sched_priority > MAX_RT_PRIO-1)    return -EINVAL;
/// if (rt_policy(policy) != (attr->sched_priority != 0))
///                                              return -EINVAL;
/// if (user) retval = user_check_sched_setscheduler(...);
/// ```
///
/// The second EINVAL is the interesting one, and Linux states the rule in
/// a comment right above it: "valid priorities for SCHED_FIFO and SCHED_RR
/// are 1..MAX_RT_PRIO-1, valid priority for SCHED_NORMAL, SCHED_BATCH and
/// SCHED_IDLE is 0". NARF reports SCHED_OTHER for every task
/// (`sys_sched_getscheduler`), so a NON-ZERO priority is always -EINVAL
/// here. It used to be stored and read back, which told a caller it had
/// been granted a real-time priority on a policy that has none.
///
/// `user_check_sched_setscheduler`'s remaining arm that bites is
/// `check_same_owner`: the caller's euid must match the target's uid or
/// euid, else CAP_SYS_NICE, else -EPERM.
///
/// LINUX-GAP: the RT arms of `user_check_sched_setscheduler` (RLIMIT_RTPRIO
/// headroom, SCHED_DEADLINE always requiring privilege) are unreachable
/// while every task is SCHED_OTHER.
pub(crate) fn sys_sched_setparam(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
    const ESRCH: i64 = 3;
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    /// `MAX_RT_PRIO - 1` (include/linux/sched/prio.h: MAX_RT_PRIO = 100).
    const MAX_RT_PRIO_MINUS_1: i32 = 99;
    let args = *ctx.args();
    // `pid_t` is `int`; reading the whole register let a negative pid
    // arrive as a huge positive value and miss the `pid < 0` guard.
    let pid = args.arg0 as i32;
    let inp = args.arg1;
    if inp == 0 || pid < 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // Read one i32 from user space under the SMAP bracket.
    let mut buf = [0u8; 4];
    // SAFETY: `inp` is the user sched_param pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the 4-byte read.
    if unsafe { copy_from_user(&mut buf, inp) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    let val = i32::from_ne_bytes(buf);
    // `pid` is resolved in the CALLER's pid namespace (Linux
    // find_process_by_pid -> find_task_by_vpid), exactly as
    // sys_sched_setaffinity does. Audit finding #18.
    let caller = current_task_id();
    let task = if pid == 0 {
        caller
    } else {
        let Some(outer) = accept_pid_from(caller, pid as u64) else {
            ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
            return;
        };
        let resolved = proc_pid_to_tid(outer);
        // `if (!p) return -ESRCH;` — `proc_pid_to_tid` falls back to the
        // identity mapping for an unregistered pid, so the existence check
        // is what implements it.
        if resolved != caller && crate::task::task_get(resolved).is_none() {
            ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
            return;
        }
        resolved
    };

    // Priority range, then the policy/priority agreement rule.
    if !(0..=MAX_RT_PRIO_MINUS_1).contains(&val) {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // `rt_policy(policy) != (attr->sched_priority != 0)`. Every NARF task
    // is SCHED_OTHER, so rt_policy is false and only 0 agrees with it.
    if val != 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }

    // `check_same_owner(p)`: the CALLER's effective uid against the
    // TARGET's real or effective uid — the same test setpriority applies.
    let caller_euid = read_uidgid(caller).euid;
    let target = read_uidgid(task);
    if target.uid != caller_euid && target.euid != caller_euid && !capable(CAP_SYS_NICE) {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }

    let mut g = SCHED_PARAM_TABLE.lock();
    let m = match g.as_mut() {
        Some(m) => m,
        None => {
            // Internal: the sched-param table is uninitialized (unreachable
            // for a live task). -EPERM is a valid setscheduler errno.
            ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
            return;
        }
    };
    m.insert(task, val);
    drop(g);
    ctx.set_return(SyscallReturn::ok(0));
}
