#[allow(unused_imports)]
use super::*;

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub(crate) fn sys_noop_ok(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}
