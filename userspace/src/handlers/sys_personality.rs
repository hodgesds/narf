#[allow(unused_imports)]
use super::*;

/// `personality(persona)` — NARF only implements the default Linux
/// execution domain (PER_LINUX = 0); report it and ignore changes.
pub(crate) fn sys_personality(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}
