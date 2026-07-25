#[allow(unused_imports)]
use super::*;

/// `syncfs(fd)` — flush the filesystem backing `fd`. No-op (see sync).
pub(crate) fn sys_syncfs(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}
