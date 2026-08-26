#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_set_tid_address(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tidptr = args.arg0;
    let me = current_task_id();
    // Per Linux: set_tid_address records the pointer regardless
    // of value; passing 0 effectively disables clear_child_tid.
    set_clear_child_tid(me, tidptr);
    // Return the caller's TID.
    ctx.set_return(SyscallReturn::ok(me));
}
