#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE1(sched_get_priority_min, int, policy)`
/// — the smallest `sched_priority` accepted for `policy`. Same `int`-width
/// and `-EINVAL`-not-`-1` corrections as `sched_get_priority_max`.
pub(crate) fn sys_sched_get_priority_min(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = 22;
    let policy = ctx.args().arg0 as i32;
    match priority_min_for_policy(policy) {
        Some(p) => ctx.set_return(SyscallReturn::ok(p as u64)),
        None => ctx.set_return(SyscallReturn::ok((-EINVAL) as u64)),
    }
}
