#[allow(unused_imports)]
use super::*;

/// `setgroups(size, list)` — accepted; NARF does not track a
/// supplementary group list, so this is structural-only.
pub(crate) fn sys_setgroups(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}
