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
/// PRIO_PGRP / PRIO_USER used to take the -EINVAL arm; the selection is
/// now shared with getpriority and the ioprio pair.
///
/// Across a set, Linux threads the error through `set_one_prio(p, niceval,
/// error)`: it starts at -ESRCH and a task that IS renicable clears it to
/// 0, while a task that is not overwrites it with -EPERM/-EACCES. So a
/// partially-permitted group reports whichever task was visited last, and
/// an empty set reports -ESRCH. That is faithfully odd, and reproduced
/// rather than tidied — a caller that renices a group it partly owns sees
/// success on Linux, and "tidying" it into an error would break that.
pub(crate) fn sys_setpriority(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
    const ESRCH: i64 = 3;
    const EACCES: i64 = 13;
    const EINVAL: i64 = 22;
    const PRIO_PROCESS: i64 = 0;
    const PRIO_PGRP: i64 = 1;
    const PRIO_USER: i64 = 2;
    let args = *ctx.args();
    // `int which`, `int who`, `int niceval` — all 32-bit.
    let which = args.arg0 as i32 as i64;
    let who = args.arg1 as i32;
    let prio = args.arg2 as i32 as i64;
    let scope = match which {
        PRIO_PROCESS => WhoScope::Process,
        PRIO_PGRP => WhoScope::Pgrp,
        PRIO_USER => WhoScope::User,
        _ => {
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
            return;
        }
    };
    // Linux clamps rather than rejecting an out-of-range niceval, and does
    // so AFTER the `which` check — so a bad `which` is -EINVAL even with a
    // wild niceval.
    let prio = prio.clamp(-20, 19);
    let targets = resolve_who_targets(scope, who, current_task_id());
    let mut result: i64 = -ESRCH;
    for task in targets {
        // `set_one_prio_perm(p)` — ownership, by the CALLER's EFFECTIVE uid
        // against the TARGET's real and effective uids.
        let caller_euid = read_uidgid(current_task_id()).euid;
        let target = read_uidgid(task);
        let owns = target.uid == caller_euid || target.euid == caller_euid;
        if !owns && !capable(CAP_SYS_NICE) {
            result = -EPERM;
            continue;
        }

        // `if (niceval < task_nice(p) && !can_nice(p, niceval)) -EACCES;`
        // Only a REDUCTION (a more favourable nice) is restricted; raising
        // nice is always allowed. `is_nice_reduction` converts the nice
        // value to rlimit style — `nice_to_rlimit(nice) = 20 - nice` — and
        // compares it against the target's RLIMIT_NICE ceiling.
        let current = i64::from(read_nice(task));
        if prio < current {
            let nice_rlim = (20 - prio) as u64;
            let ceiling = read_rlimit(task, RLIMIT_NICE).map(|l| l.cur).unwrap_or(0);
            if nice_rlim > ceiling && !capable(CAP_SYS_NICE) {
                result = -EACCES;
                continue;
            }
        }

        if write_nice(task, prio as i32) {
            result = 0;
        } else {
            // Internal: the nice table is uninitialized (unreachable for a
            // live task). -EPERM is set_one_prio's failure errno.
            result = -EPERM;
        }
    }
    ctx.set_return(SyscallReturn::ok(result as u64));
}
