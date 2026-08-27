#[allow(unused_imports)]
use super::*;

/// `setpriority(which, who, niceval)` — Linux `SYSCALL_DEFINE3(setpriority)`
/// (kernel/sys.c):
///   - `which` outside `[PRIO_PROCESS, PRIO_USER]` → -EINVAL,
///   - `niceval` is CLAMPED to `[MIN_NICE(-20), MAX_NICE(19)]`, never rejected,
///   - the target pid is resolved in the caller's pid ns; not found → -ESRCH.
///
/// Then `set_one_prio` applies TWO distinct permission checks, and the fact
/// that they carry different errnos is the whole reason to implement both:
///
/// ```text
/// if (!set_one_prio_perm(p)) { error = -EPERM;  goto out; }
/// if (niceval < task_nice(p) && !can_nice(p, niceval))
///                             { error = -EACCES; goto out; }
/// ```
///
/// with
///
/// ```text
/// static bool set_one_prio_perm(struct task_struct *p) {
///         if (uid_eq(pcred->uid, cred->euid) ||
///             uid_eq(pcred->euid, cred->euid))   return true;
///         if (ns_capable(pcred->user_ns, CAP_SYS_NICE)) return true;
///         return false;
/// }
/// int can_nice(const struct task_struct *p, const int nice) {
///         return is_nice_reduction(p, nice) || capable(CAP_SYS_NICE);
/// }
/// ```
///
/// -EPERM means "that is not your process". -EACCES means "it is yours, but
/// you may not make it MORE favourable". `renice` reports them differently
/// and a user acting on the first would go looking for the wrong problem.
///
/// LINUX-GAP: PRIO_PGRP / PRIO_USER (group and user renice) are still
/// unimplemented and take the -EINVAL above.
pub(crate) fn sys_setpriority(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
    const ESRCH: i64 = 3;
    const EACCES: i64 = 13;
    const EINVAL: i64 = 22;
    let args = *ctx.args();
    let which = args.arg0 as i64;
    let who = args.arg1;
    let prio = args.arg2 as i64;
    if which != PRIO_PROCESS_VAL {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // Linux clamps rather than rejecting an out-of-range niceval.
    let prio = prio.clamp(-20, 19);
    // PRIO_PROCESS `who` is a pid in the CALLER's pid namespace (Linux
    // kernel/sys.c:282 find_task_by_vpid); who == 0 means the caller. Resolve
    // it instead of discarding it, so `renice -p N` renices N, not the caller.
    // Audit finding #28.
    let task = if who == 0 {
        current_task_id()
    } else {
        let Some(outer) = accept_pid_from(current_task_id(), who) else {
            ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
            return;
        };
        proc_pid_to_tid(outer)
    };

    // `set_one_prio_perm(p)` — ownership, by the CALLER's EFFECTIVE uid
    // against the TARGET's real and effective uids.
    let caller_euid = read_uidgid(current_task_id()).euid;
    let target = read_uidgid(task);
    let owns = target.uid == caller_euid || target.euid == caller_euid;
    if !owns && !capable(CAP_SYS_NICE) {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }

    // `if (niceval < task_nice(p) && !can_nice(p, niceval)) -EACCES;`
    // Only a REDUCTION (a more favourable nice) is restricted; raising nice
    // is always allowed. `is_nice_reduction` converts the nice value to
    // rlimit style — `nice_to_rlimit(nice) = 20 - nice` — and compares it
    // against the target's RLIMIT_NICE ceiling.
    let current = read_nice(task) as i64;
    if prio < current {
        let nice_rlim = (20 - prio) as u64;
        let ceiling = read_rlimit(task, RLIMIT_NICE).map(|l| l.cur).unwrap_or(0);
        if nice_rlim > ceiling && !capable(CAP_SYS_NICE) {
            ctx.set_return(SyscallReturn::ok((-EACCES) as u64));
            return;
        }
    }

    if write_nice(task, prio as i32) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        // Internal: the nice table is uninitialized (unreachable for a live
        // task). -EPERM is set_one_prio's permission-failure errno.
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
    }
}
