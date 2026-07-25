#[allow(unused_imports)]
use super::*;

/// `listxattr(path, list, size)`.
pub(crate) fn sys_listxattr(ctx: &mut dyn TrapContext) {
    match xattr_user_path(ctx.args().arg0) {
        Some(p) => xattr_list_core(p, ctx),
        None => ctx.set_return(SyscallReturn::ok((-14i64) as u64)), // EFAULT
    }
}
