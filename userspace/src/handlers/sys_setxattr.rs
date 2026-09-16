#[allow(unused_imports)]
use super::*;

/// `setxattr(path, name, value, size, flags)`.
///
/// `SYSCALL_DEFINE5(setxattr)` is one line in Linux:
/// `return path_setxattrat(AT_FDCWD, pathname, 0, name, value, size, flags);`
/// — the plain, `l`, `f` and `*at` forms are four presets of one body, and
/// keeping that shape here is what stops the permission and namespace rules
/// from drifting between them.
pub(crate) fn sys_setxattr(ctx: &mut dyn TrapContext) {
    xattr_set_at(AT_FDCWD_ARG, ctx.args().arg0, 0, ctx);
}

/// `lsetxattr(path, name, value, size, flags)` —
/// `path_setxattrat(AT_FDCWD, pathname, AT_SYMLINK_NOFOLLOW, ...)`.
pub(crate) fn sys_lsetxattr(ctx: &mut dyn TrapContext) {
    xattr_set_at(AT_FDCWD_ARG, ctx.args().arg0, AT_SYMLINK_NOFOLLOW_ARG, ctx);
}
