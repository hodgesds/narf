#[allow(unused_imports)]
use super::*;

/// `getgroups(size, list)` — NARF carries no supplementary groups, so
/// the count is always 0 (whether querying the count with size==0 or
/// filling the list).
pub(crate) fn sys_getgroups(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}
