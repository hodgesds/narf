#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getgid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    ctx.set_return(SyscallReturn::ok(
        gid_to_user(task, read_uidgid(task).gid) as u64
    ));
}
