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
/// `file_permission(MAY_EXEC | MAY_CHDIR)` runs LAST, after both of those,
/// so a bad descriptor is still -EBADF and a non-directory still -ENOTDIR
/// for a caller that also lacks search permission.
pub(crate) fn sys_fchdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux declares `unsigned int fd`, so a negative fd wraps to a huge
    // index and misses the table — EBADF, same as Linux.
    let fd = args.arg0 as u32;
    let task = current_task_id();
    // `if (fd_empty(f)) return -EBADF;` — the table decides EBADF before
    // anything looks at a path.
    let Some(dir_of_fd) = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.as_dir())).flatten()
    else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    // Linux fchdir never re-walks the path: `d_can_lookup()` asks the
    // fd's OWN file. A non-directory descriptor (pipe, socket, regular
    // file) has no `DirOps` — -ENOTDIR. This also means the answer comes
    // from the object the fd pinned, never -ENOENT for a concurrently
    // removed name. (The path re-resolution this replaces was a second
    // full walk per fchdir — the chdir stressor pays it 2×/iteration.)
    let Some(dir) = dir_of_fd else {
        ctx.set_return(errno_ret(ENOTDIR));
        return;
    };
    // The cwd is stored as a path string, so a directory fd NARF cannot
    // name (a detached fsmount) keeps its historical -ENOTDIR.
    let path = match fd_path_for_task(task, fd) {
        Some(p) if p.starts_with('/') => p,
        _ => {
            ctx.set_return(errno_ret(ENOTDIR));
            return;
        }
    };
    // Store the USER view (chroot applies exactly once at resolution —
    // see resolve_cwd_path_user).
    let user_abs = resolve_cwd_path_user(task, &path);
    // `error = file_permission(fd_file(f), MAY_EXEC | MAY_CHDIR);` — the
    // same search check sys_chdir applies to its target. Holding an open
    // descriptor is not itself authority to make the directory a cwd:
    // permissions can have changed since the open, and Linux re-checks
    // here rather than trusting the fd. The fd's own directory answers
    // with its LIVE owners/mode, so a chmod after the open is honoured.
    if !dir_search_permitted_resolved(&*dir, task) {
        ctx.set_return(errno_ret(EACCES));
        return;
    }
    task_map_set(&CWD_TABLE, task, user_abs);
    ctx.set_return(SyscallReturn::ok(0));
}
