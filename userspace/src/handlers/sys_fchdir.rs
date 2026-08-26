#[allow(unused_imports)]
use super::*;

/// `fchdir(fd)` — x86_64 81, aarch64 50. Chdir to the directory a fd
/// was opened on: glibc's fts/nftw walkers (`rm -r`, `find`) and the
/// save-cwd/restore-cwd idiom depend on it. The fd's open path comes
/// from the same fd→path record `/proc/[pid]/fd` readlinks
/// (chroot-stripped user view), then the tail is exactly sys_chdir:
/// resolve, verify it names a directory, install.
///
/// `fs/open.c::SYSCALL_DEFINE1(fchdir)` fixes the errnos and their order:
///
/// ```text
///     if (fd_empty(f))                                  return -EBADF;
///     if (!d_can_lookup(fd_file(f)->f_path.dentry))     return -ENOTDIR;
///     error = file_permission(fd_file(f), MAY_EXEC | MAY_CHDIR);
/// ```
///
/// EBADF beats ENOTDIR, which is what the two arms below already do — a
/// descriptor the table does not know is EBADF, one that resolves to a
/// non-directory is ENOTDIR. Neither is EPERM: `rm -r` restores its saved
/// cwd with `fchdir` and treats a failure there as fatal, so the errno is
/// what tells the caller "the fd went away" from "you handed me a file".
///
/// LINUX-GAP: -EACCES from `file_permission(MAY_EXEC|MAY_CHDIR)` on a
/// search-forbidden directory is not modelled here.
pub(crate) fn sys_fchdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux declares `unsigned int fd`, so a negative fd wraps to a huge
    // index and misses the table — EBADF, same as Linux.
    let fd = args.arg0 as u32;
    let task = current_task_id();
    let path = match fd_path_for_task(task, fd) {
        // fd_path_of falls back to a type_name for pathless fds
        // (pipes, sockets, …) — those never start with '/' and are
        // ENOTDIR, same as Linux fchdir on a non-directory fd.
        Some(p) if p.starts_with('/') => p,
        Some(_) => {
            ctx.set_return(SyscallReturn::ok((-20i64) as u64)); // -ENOTDIR
            return;
        }
        None => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
    };
    // Validate chroot-resolved; store the USER view (chroot applies
    // exactly once at resolution — see resolve_cwd_path_user).
    let user_abs = resolve_cwd_path_user(task, &path);
    let abs = resolve_cwd_path(task, &path);
    if resolve_dir_absolute(&abs).is_none() {
        // The descriptor exists but its path does not name a directory —
        // `d_can_lookup()` failing, i.e. -ENOTDIR (never -ENOENT: the fd
        // pinned the object, so it cannot have gone missing).
        ctx.set_return(SyscallReturn::ok((-20i64) as u64)); // -ENOTDIR
        return;
    }
    task_map_set(&CWD_TABLE, task, user_abs);
    ctx.set_return(SyscallReturn::ok(0));
}
