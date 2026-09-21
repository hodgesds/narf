#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_restart_syscall(ctx: &mut dyn TrapContext) {
    ctx.set_return(errno_ret(EINTR));
}
