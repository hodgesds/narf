#[allow(unused_imports)]
use super::*;

/// `removexattr(path, name)`.
pub(crate) fn sys_removexattr(ctx: &mut dyn TrapContext) {
    match xattr_user_path(ctx.args().arg0) {
        Some(p) => xattr_remove_core(p, ctx),
        None => ctx.set_return(SyscallReturn::ok((-14i64) as u64)), // EFAULT
    }
}
