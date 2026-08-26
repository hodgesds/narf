#[allow(unused_imports)]
use super::*;

/// `fstatat(dirfd, pathname, statbuf, flags)`.
///
/// The dirfd was previously DISCARDED (`let _dirfd = args.arg0;`) and this
/// proxied to `sys_stat` with the raw user pointer, so a relative path was
/// resolved against the CWD instead of the named directory.
///
/// `fstatat` is one of the most heavily used syscalls on a systemd system:
/// sd-device walks sysfs a component at a time against parent-directory
/// fds, and glibc implements `stat()`/`lstat()` on top of it. With the
/// dirfd ignored a relative lookup either fails or, worse, silently stats a
/// same-named file in the wrong directory and returns ITS metadata.
///
/// AT_EMPTY_PATH (an empty path naming the dirfd itself) is handled by
/// resolving the descriptor's own path.
///
/// SHADOWED under `linux-compat`: `install_core_syscalls` re-installs
/// [`sys_newfstatat_linux`] over `Syscall::Newfstatat`, so this body is only
/// reachable in the non-`linux-compat` build.
///
/// `fs/stat.c::SYSCALL_DEFINE4(newfstatat)` → `vfs_fstatat` → `cp_new_stat`
/// resolves the path BEFORE copying, so a bad `statbuf` cannot pre-empt the
/// lookup's -EBADF/-ENOTDIR/-ENOENT; the null-buffer check therefore lives in
/// [`stat_absolute`], after resolution. It used to sit first here and answer
/// the bare -1, i.e. EPERM.
pub(crate) fn sys_newfstatat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int fstatat(int dirfd, const char *pathname,
    // struct stat *statbuf, int flags)`.
    let dirfd = args.arg0 as i64;
    let path_uptr = args.arg1;
    let out_ptr = args.arg2 as *mut StatBuf;
    let _flags = args.arg3;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let task = current_task_id();
    // AT_EMPTY_PATH: stat the descriptor itself.
    let joined = if path_str.is_empty() {
        match fd_path_for_task(task, dirfd as u32) {
            Some(p) if dirfd >= 0 && p.starts_with('/') => p,
            _ => {
                ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
                return;
            }
        }
    } else {
        match resolve_at_path(task, dirfd, &path_str) {
            Ok(p) => p,
            Err(e) => {
                ctx.set_return(SyscallReturn::ok(e as u64));
                return;
            }
        }
    };
    let path = apply_chroot(&joined);
    stat_absolute(ctx, &path, out_ptr);
}
