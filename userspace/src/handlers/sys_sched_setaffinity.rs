#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sched_setaffinity(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let _pid = args.arg0;
    let size = args.arg1 as usize;
    let buf = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if buf == 0 || size == 0 {
        ctx.set_return(fail);
        return;
    }
    // Validate the user pointer range but discard the value — we don't pin.
    if validate_user_range(buf, size.min(8)).is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
