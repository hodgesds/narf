#[allow(unused_imports)]
use super::*;

/// `getpriority(which, who)` — Linux `SYSCALL_DEFINE2(getpriority)`
/// (kernel/sys.c):
///   - `which` outside `[PRIO_PROCESS, PRIO_USER]` → -EINVAL,
///   - the target pid is resolved in the caller's pid ns; not found → -ESRCH,
///   - the value is `nice_to_rlimit(nice) = 20 - nice`, so nice -20..=19 maps
///     to the wire range 40..=1 (never negative, so it can't be mistaken for
///     an errno — glibc recovers the nice with `20 - ret`).
/// LINUX-GAP: PRIO_PGRP/PRIO_USER (group/user queries) are unimplemented (also
/// -EINVAL here).
pub(crate) fn sys_getpriority(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i64;
    let who = args.arg1;
    if which != PRIO_PROCESS_VAL {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    // PRIO_PROCESS `who` is a pid in the CALLER's pid namespace (Linux
    // kernel/sys.c:282); who == 0 means the caller. Resolve it instead of
    // discarding it, so `renice`/`getpriority -p N` reports N. Audit finding
    // #28.
    let task = if who == 0 {
        current_task_id()
    } else {
        let Some(outer) = accept_pid_from(current_task_id(), who) else {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        };
        proc_pid_to_tid(outer)
    };
    let nice = read_nice(task);
    // Linux nice_to_rlimit: the wire value is `20 - nice` (a -20..=19 nice maps
    // to 40..=1), matching what glibc's getpriority() unwraps with `20 - ret`.
    let wire = (20 - nice) as u64;
    ctx.set_return(SyscallReturn::ok(wire));
}
