#[allow(unused_imports)]
use super::*;

#[cfg(feature = "container")]
pub(crate) fn sys_shmget(ctx: &mut dyn TrapContext) {
    let key = ctx.args().arg0 as u32;
    let task = current_task_id();
    let ns = current_or_default_ipc_ns(task);
    ctx.set_return(SyscallReturn::ok(ns.shmget(key) as u64));
}
