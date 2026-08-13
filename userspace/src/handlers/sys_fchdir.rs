#[allow(unused_imports)]
use super::*;

/// `fchdir(fd)` — x86_64 81, aarch64 50. Chdir to the directory a fd
/// was opened on: glibc's fts/nftw walkers (`rm -r`, `find`) and the
/// save-cwd/restore-cwd idiom depend on it. The fd's open path comes
/// from the same fd→path record `/proc/[pid]/fd` readlinks
/// (chroot-stripped user view), then the tail is exactly sys_chdir:
/// resolve, verify it names a directory, install.
pub(crate) fn sys_fchdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let task = current_task_id();
    let path = match fd_path_for_task(task, fd) {
        // fd_path_of falls back to a type_name for pathless fds
        // (pipes, sockets, …) — those never start with '/' and are
        // ENOTDIR, same as Linux fchdir on a non-directory fd.
        Some(p) if p.starts_with('/') => p,
        Some(_) => {
            ctx.set_return(SyscallReturn::ok((-20i64) as u64)); // ENOTDIR
            return;
        }
        None => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        }
    };
    // Validate chroot-resolved; store the USER view (chroot applies
    // exactly once at resolution — see resolve_cwd_path_user).
    let user_abs = resolve_cwd_path_user(task, &path);
    let abs = resolve_cwd_path(task, &path);
    if resolve_dir_absolute(&abs).is_none() {
        ctx.set_return(SyscallReturn::ok((-20i64) as u64)); // ENOTDIR
        return;
    }
    task_map_set(&CWD_TABLE, task, user_abs);
    ctx.set_return(SyscallReturn::ok(0));
}
