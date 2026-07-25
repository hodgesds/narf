#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getpriority(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i64;
    let _who = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if which != PRIO_PROCESS_VAL {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let nice = read_nice(task);
    // Linux convention: getpriority returns the value pre-shifted
    // by +20 so a -20..=19 nice maps to 0..=39 on the wire — the
    // user-side libc subtracts 20 to recover the signed value.
    // Errors then surface as the wire -1 distinct from a value of 19.
    let shifted = (nice + 20) as u64;
    ctx.set_return(SyscallReturn::ok(shifted));
}
