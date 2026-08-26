#[allow(unused_imports)]
use super::*;

/// `setpriority(which, who, niceval)` — Linux `SYSCALL_DEFINE3(setpriority)`
/// (kernel/sys.c):
///   - `which` outside `[PRIO_PROCESS, PRIO_USER]` → -EINVAL,
///   - `niceval` is CLAMPED to `[MIN_NICE(-20), MAX_NICE(19)]`, never rejected,
///   - the target pid is resolved in the caller's pid ns; not found → -ESRCH.
/// LINUX-GAP: PRIO_PGRP/PRIO_USER (group/user renice) are unimplemented (also
/// -EINVAL here), and set_one_prio's permission checks (-EPERM for a foreign
/// uid, -EACCES for lowering nice without CAP_SYS_NICE) are not modelled.
pub(crate) fn sys_setpriority(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i64;
    let who = args.arg1;
    let prio = args.arg2 as i64;
    if which != PRIO_PROCESS_VAL {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
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
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        };
        proc_pid_to_tid(outer)
    };
    if write_nice(task, prio as i32) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        // Internal: the nice table is uninitialized (unreachable for a live
        // task). -EPERM is set_one_prio's permission-failure errno.
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
    }
}
