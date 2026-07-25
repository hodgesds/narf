#[allow(unused_imports)]
use super::*;

/// `clock_adjtime(clockid, timex)` — per-clock adjtimex. Only the
/// settable system clocks are accepted.
pub(crate) fn sys_clock_adjtime(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let clockid = a.arg0;
    // CLOCK_REALTIME(0)/MONOTONIC(1)/BOOTTIME(7)/TAI(11) are accepted.
    match clockid {
        0 | 1 | 7 | 11 => {}
        _ => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
    }
    let r = adjtimex_core(a.arg1);
    ctx.set_return(SyscallReturn::ok(r as u64));
}
