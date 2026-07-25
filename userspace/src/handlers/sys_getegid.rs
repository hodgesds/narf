#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getegid(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(
        read_uidgid(current_task_id()).egid as u64,
    ));
}
