#[allow(unused_imports)]
use super::*;

/// `setxattr(path, name, value, size, flags)`.
pub(crate) fn sys_setxattr(ctx: &mut dyn TrapContext) {
    match xattr_user_path(ctx.args().arg0) {
        Some(p) => xattr_set_core(p, ctx),
        None => ctx.set_return(SyscallReturn::ok((-14i64) as u64)), // EFAULT
    }
}
