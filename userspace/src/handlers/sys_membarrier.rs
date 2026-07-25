#[allow(unused_imports)]
use super::*;

/// `membarrier(cmd, flags, cpu_id)` — process-wide memory barrier.
/// QUERY (0) returns the supported-command bitmask; the actual barrier
/// commands are no-ops on the cooperative single-CPU kernel (loads and
/// stores are already globally ordered when a task is in flight).
pub(crate) fn sys_membarrier(ctx: &mut dyn TrapContext) {
    let cmd = ctx.args().arg0 as u32;
    const QUERY: u32 = 0;
    const GLOBAL: u32 = 1 << 0;
    const GLOBAL_EXPEDITED: u32 = 1 << 1;
    const REGISTER_GLOBAL_EXPEDITED: u32 = 1 << 2;
    const PRIVATE_EXPEDITED: u32 = 1 << 3;
    const REGISTER_PRIVATE_EXPEDITED: u32 = 1 << 4;
    let supported = GLOBAL
        | GLOBAL_EXPEDITED
        | REGISTER_GLOBAL_EXPEDITED
        | PRIVATE_EXPEDITED
        | REGISTER_PRIVATE_EXPEDITED;
    let r: u64 = if cmd == QUERY {
        supported as u64
    } else if cmd & supported == cmd && cmd.is_power_of_two() {
        0 // barrier / registration is a no-op here
    } else {
        (-22i64) as u64 // EINVAL
    };
    ctx.set_return(SyscallReturn::ok(r));
}
