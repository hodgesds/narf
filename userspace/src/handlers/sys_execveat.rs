#[allow(unused_imports)]
use super::*;

/// `execveat(dirfd, path, argv, envp, flags)` — execve relative to a
/// dirfd. NARF resolves absolute paths (and AT_FDCWD) only, so the dirfd
/// and flags are dropped and the call is forwarded to `sys_execve` with
/// the `(path, argv, envp)` layout it expects.
pub(crate) fn sys_execveat(ctx: &mut dyn TrapContext) {
    // Linux: execveat(dirfd, path, argv, envp, flags).
    let a = *ctx.args();
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const AT_EXECVE_CHECK: u64 = 0x10000;
    if a.arg4 & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_EXECVE_CHECK) != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let dirfd = a.arg0 as i32;
    // A NULL path POINTER is invalid (fexecve passes a valid pointer to an
    // empty string, never NULL). Empty-string handling is below.
    if a.arg1 == 0 {
        // NULL path pointer faults → EFAULT.
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    // A pointer that FAULTS is not an empty path. `unwrap_or_default()` made
    // the two indistinguishable, and the AT_EMPTY_PATH branch below then read
    // an unreadable pointer as the fexecve form and executed the dirfd's
    // binary — a silent substitution where Linux's `getname_flags` returns
    // -EFAULT. An empty STRING still arrives as `Ok("")` and keeps its
    // meaning.
    let path_str = match copy_user_cstr_checked(a.arg1, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let task = current_task_id();

    if path_str.is_empty() {
        if a.arg4 & AT_EMPTY_PATH == 0 {
            ctx.set_return(errno_ret(ENOENT));
            return;
        }
        const AT_FDCWD_I32: i32 = -100;
        if dirfd == AT_FDCWD_I32 {
            ctx.set_return(errno_ret(EACCES));
            return;
        }
        if dirfd < 0 {
            ctx.set_return(errno_ret(EBADF));
            return;
        }
        let is_open =
            fd::with_table(task, |t| t.get(dirfd as u32).is_some()).unwrap_or(false);
        if !is_open {
            ctx.set_return(errno_ret(EBADF));
            return;
        }
        if let Some(p) = fd_path_for_task(task, dirfd as u32) {
            do_execve_resolved(ctx, p, a.arg2, a.arg3, None);
            return;
        }
        // No filesystem path for the fd. For an AT_EMPTY_PATH fexecve this is the
        // memfd case (systemd seals its sd-executor into a memfd and fexecve's it):
        // read the ELF straight out of the fd's FileOps and exec those bytes.
        if let Some(bytes) = read_fd_image(task, dirfd as u32) {
            let label = alloc::format!("/proc/self/fd/{}", dirfd);
            do_execve_resolved(ctx, label, a.arg2, a.arg3, Some(bytes));
            return;
        }
        ctx.set_return(errno_ret(ENOENT));
        return;
    }

    let resolved = match resolve_at_path(task, dirfd as i64, &path_str) {
        Ok(p) => p,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    do_execve_resolved(ctx, resolved, a.arg2, a.arg3, None);
}
