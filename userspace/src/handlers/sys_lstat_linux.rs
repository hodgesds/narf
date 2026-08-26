#[allow(unused_imports)]
use super::*;

/// `fs/stat.c::SYSCALL_DEFINE2(newlstat)` — identical to `newstat` except
/// that `vfs_lstat` passes `AT_SYMLINK_NOFOLLOW`, so the errno set and its
/// order are the same: -EFAULT for the pathname, -ENOENT for a name that
/// resolves to nothing, then -EFAULT for the destination copy. See
/// [`sys_stat_linux`] for why the bare -1 (EPERM) mattered.
///
/// LIVE handler for `Syscall::Lstat` under `linux-compat`; it replaces the
/// NARF-shape [`sys_stat`] that `install_core_syscalls` puts there first.
pub(crate) fn sys_lstat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int lstat(const char *pathname, struct stat *statbuf)`.
    // lstat is stat-that-does-not-follow: describe the symlink itself.
    stat_linux_common(ctx, args.arg0, args.arg1, false);
}
