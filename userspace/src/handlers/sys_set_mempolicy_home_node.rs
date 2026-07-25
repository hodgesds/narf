#[allow(unused_imports)]
use super::*;

/// `set_mempolicy_home_node(addr, len, home_node, flags)` — set a range's
/// home NUMA node. Accepted (no per-range home binding yet); flags must
/// be 0.
pub(crate) fn sys_set_mempolicy_home_node(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    if a.arg3 != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
