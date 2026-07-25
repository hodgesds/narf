#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sched_get_priority_min(ctx: &mut dyn TrapContext) {
    let policy = ctx.args().arg0;
    match priority_min_for_policy(policy) {
        Some(p) => ctx.set_return(SyscallReturn::ok(p as u64)),
        None => ctx.set_return(SyscallReturn::ok((-1i64) as u64)),
    }
}
