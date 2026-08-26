#[allow(unused_imports)]
use super::*;

/// `fs/stat.c::SYSCALL_DEFINE2(newstat)`:
///
/// ```text
///     error = vfs_stat(filename, &stat);
///     if (unlikely(error)) return error;
///     return cp_new_stat(&stat, statbuf);
/// ```
///
/// LIVE handler for `Syscall::Stat` under `linux-compat` (it is installed
/// over the NARF-shape [`sys_stat`]). The errnos are decided by the shared
/// `stat_linux_common`/`stat_linux_path` body: a faulting or NULL pathname is
/// -EFAULT, a path that resolves to nothing is -ENOENT, and a destination the
/// copy cannot reach is -EFAULT. None of them is the bare -1 that libc reads
/// as EPERM — which is what a shell's PATH search over `:`-separated
/// candidates depends on, since it must keep walking on ENOENT and stop on a
/// real permission failure.
pub(crate) fn sys_stat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int stat(const char *pathname, struct stat *statbuf)`.
    // Plain stat always follows a trailing symlink.
    stat_linux_common(ctx, args.arg0, args.arg1, true);
}
