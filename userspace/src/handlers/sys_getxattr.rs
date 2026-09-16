#[allow(unused_imports)]
use super::*;

/// `getxattr(path, name, value, size)` —
/// `path_getxattrat(AT_FDCWD, pathname, 0, ...)`.
pub(crate) fn sys_getxattr(ctx: &mut dyn TrapContext) {
    xattr_get_at(AT_FDCWD_ARG, ctx.args().arg0, 0, ctx);
}

/// `lgetxattr(path, name, value, size)` —
/// `path_getxattrat(AT_FDCWD, pathname, AT_SYMLINK_NOFOLLOW, ...)`.
pub(crate) fn sys_lgetxattr(ctx: &mut dyn TrapContext) {
    xattr_get_at(AT_FDCWD_ARG, ctx.args().arg0, AT_SYMLINK_NOFOLLOW_ARG, ctx);
}
