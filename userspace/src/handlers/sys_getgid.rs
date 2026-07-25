#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getgid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    ctx.set_return(SyscallReturn::ok(read_uidgid(task).gid as u64));
}
