#[allow(unused_imports)]
use super::*;

/// `flistxattr(fd, list, size)`.
pub(crate) fn sys_flistxattr(ctx: &mut dyn TrapContext) {
    match xattr_fd_key(ctx.args().arg0 as u32) {
        Some(p) => xattr_list_core(p, ctx),
        None => ctx.set_return(SyscallReturn::ok((-9i64) as u64)), // EBADF
    }
}
