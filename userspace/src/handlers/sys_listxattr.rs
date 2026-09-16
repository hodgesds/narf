#[allow(unused_imports)]
use super::*;

/// `listxattr(path, list, size)` —
/// `path_listxattrat(AT_FDCWD, pathname, 0, ...)`.
pub(crate) fn sys_listxattr(ctx: &mut dyn TrapContext) {
    xattr_list_at(AT_FDCWD_ARG, ctx.args().arg0, 0, ctx);
}

/// `llistxattr(path, list, size)` —
/// `path_listxattrat(AT_FDCWD, pathname, AT_SYMLINK_NOFOLLOW, ...)`.
pub(crate) fn sys_llistxattr(ctx: &mut dyn TrapContext) {
    xattr_list_at(AT_FDCWD_ARG, ctx.args().arg0, AT_SYMLINK_NOFOLLOW_ARG, ctx);
}
