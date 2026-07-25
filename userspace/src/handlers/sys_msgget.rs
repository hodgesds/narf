#[allow(unused_imports)]
use super::*;

#[cfg(all(feature = "container", not(feature = "linux-compat")))]
pub(crate) fn sys_msgget(ctx: &mut dyn TrapContext) {
    let key = ctx.args().arg0 as u32;
    let task = current_task_id();
    let ns = current_or_default_ipc_ns(task);
    ctx.set_return(SyscallReturn::ok(ns.msgget(key) as u64));
}
