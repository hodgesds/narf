#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setpriority(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i64;
    let who = args.arg1;
    let prio = args.arg2 as i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if which != PRIO_PROCESS_VAL || !(-20..=19).contains(&prio) {
        ctx.set_return(fail);
        return;
    }
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
        ctx.set_return(fail);
    }
}
