#[allow(unused_imports)]
use super::*;

/// `fsetxattr(fd, name, value, size, flags)` — `path_setxtrat(fd, NULL, AT_EMPTY_PATH, ...)`.
///
/// The `f` forms are the AT_EMPTY_PATH preset: a NULL pathname sends
/// `path_*xattrat` down its `fd_file(f)` branch, which is why an invalid
/// descriptor is -EBADF there and not -ENOENT.
pub(crate) fn sys_fsetxattr(ctx: &mut dyn TrapContext) {
    xattr_set_at(ctx.args().arg0 as i64, 0, AT_EMPTY_PATH_ARG, ctx);
}
