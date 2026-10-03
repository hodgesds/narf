#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_set_tid_address(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tidptr = args.arg0;
    let me = current_task_id();
    // Per Linux: set_tid_address records the pointer regardless
    // of value; passing 0 effectively disables clear_child_tid.
    set_clear_child_tid(me, tidptr);
    // Return the caller's thread ID, the value gettid(2) returns, not the
    // scheduler TaskId: musl's `__init_tp` stores it as the thread's `tid`,
    // which `raise` and `pthread_kill` pass to tkill.
    ctx.set_return(SyscallReturn::ok(linux_tid_for_task(me)));
}
