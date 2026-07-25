#[allow(unused_imports)]
use super::*;

/// `sched_getscheduler(pid)` — NARF runs one cooperative policy,
/// reported as SCHED_OTHER (0).
pub(crate) fn sys_sched_getscheduler(_ctx: &mut dyn TrapContext) {
    _ctx.set_return(SyscallReturn::ok(0));
}
