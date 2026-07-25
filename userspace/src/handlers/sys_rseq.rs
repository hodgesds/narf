#[allow(unused_imports)]
use super::*;

/// `rseq(rseq, len, flags, sig)` — register/unregister a restartable-
/// sequence area. NARF is a cooperative single-CPU kernel with no
/// preemption mid-sequence, so there is nothing to restart; accept the
/// registration (glibc registers rseq at thread start and expects
/// success or a clean ENOSYS).
pub(crate) fn sys_rseq(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}
