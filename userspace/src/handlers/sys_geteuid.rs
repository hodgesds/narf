#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_geteuid(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(
        read_uidgid(current_task_id()).euid as u64,
    ));
}
