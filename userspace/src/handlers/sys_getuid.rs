#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getuid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    ctx.set_return(SyscallReturn::ok(read_uidgid(task).uid as u64));
}
