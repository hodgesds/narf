#[allow(unused_imports)]
use super::*;

/// `getxattr(path, name, value, size)`.
pub(crate) fn sys_getxattr(ctx: &mut dyn TrapContext) {
    match xattr_user_path(ctx.args().arg0) {
        Some(p) => xattr_get_core(p, ctx),
        None => ctx.set_return(SyscallReturn::ok((-14i64) as u64)), // EFAULT
    }
}
