#[allow(unused_imports)]
use super::*;

/// `removexattr(path, name)` —
/// `path_removexattrat(AT_FDCWD, pathname, 0, name)`.
pub(crate) fn sys_removexattr(ctx: &mut dyn TrapContext) {
    xattr_remove_at(AT_FDCWD_ARG, ctx.args().arg0, 0, ctx);
}

/// `lremovexattr(path, name)` —
/// `path_removexattrat(AT_FDCWD, pathname, AT_SYMLINK_NOFOLLOW, name)`.
pub(crate) fn sys_lremovexattr(ctx: &mut dyn TrapContext) {
    xattr_remove_at(AT_FDCWD_ARG, ctx.args().arg0, AT_SYMLINK_NOFOLLOW_ARG, ctx);
}
