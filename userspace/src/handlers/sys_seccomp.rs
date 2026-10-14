#[allow(unused_imports)]
use super::*;

/// `SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags, void
/// __user *, uargs)` — `op` and `flags` are `unsigned int`, so only their low
/// 32 bits are the caller's request. See `crate::seccomp`.
pub(crate) fn sys_seccomp(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    ctx.set_return(crate::seccomp::do_seccomp(
        args.arg0 as u32,
        args.arg1 as u32,
        args.arg2,
    ));
}
