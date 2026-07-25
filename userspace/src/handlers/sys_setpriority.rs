#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setpriority(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i64;
    let _who = args.arg1;
    let prio = args.arg2 as i64;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if which != PRIO_PROCESS_VAL || !(-20..=19).contains(&prio) {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    if write_nice(task, prio as i32) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}
