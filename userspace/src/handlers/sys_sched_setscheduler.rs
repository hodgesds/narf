#[allow(unused_imports)]
use super::*;

/// `sched_setscheduler(pid, policy, param)` — accept any of the
/// standard policy numbers (the cooperative scheduler doesn't
/// distinguish them); reject unknown ones with EINVAL.
pub(crate) fn sys_sched_setscheduler(ctx: &mut dyn TrapContext) {
    let policy = ctx.args().arg1 as i32;
    // SCHED_OTHER=0, FIFO=1, RR=2, BATCH=3, IDLE=5.
    if matches!(policy, 0 | 1 | 2 | 3 | 5) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
    }
}
