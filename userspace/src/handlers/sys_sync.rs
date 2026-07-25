#[allow(unused_imports)]
use super::*;

/// `sync()` — flush all filesystems. NARF's in-memory FSes have no
/// write-back, so this is a no-op.
pub(crate) fn sys_sync(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}
