#[allow(unused_imports)]
use super::*;

/// `adjtimex(timex)`.
pub(crate) fn sys_adjtimex(ctx: &mut dyn TrapContext) {
    let r = adjtimex_core(ctx.args().arg0);
    ctx.set_return(SyscallReturn::ok(r as u64));
}
