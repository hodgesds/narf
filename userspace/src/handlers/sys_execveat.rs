#[allow(unused_imports)]
use super::*;

/// `execveat(dirfd, path, argv, envp, flags)` — execve relative to a
/// dirfd. NARF resolves absolute paths (and AT_FDCWD) only, so the dirfd
/// and flags are dropped and the call is forwarded to `sys_execve` with
/// the `(path, argv, envp)` layout it expects.
pub(crate) fn sys_execveat(ctx: &mut dyn TrapContext) {
    // Linux: execveat(dirfd, path, argv, envp, flags).
    let a = *ctx.args();
    let dirfd = a.arg0 as i32;
    // A NULL path POINTER is invalid (fexecve passes a valid pointer to an
    // empty string, never NULL). Empty-string handling is below.
    if a.arg1 == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let path_str = copy_user_cstr(a.arg1, 4096).unwrap_or_default();
    let path_empty = path_str.is_empty();
    const AT_EMPTY_PATH: u64 = 0x1000;
    let task = current_task_id();

    // Resolve the image path:
    //   - empty path + AT_EMPTY_PATH → the binary the dirfd itself refers to
    //     (fexecve(3): open the executable, then execveat(fd,"",…,AT_EMPTY_PATH).
    //     systemd 257 spawns its sd-executor and every service exactly this way).
    //   - absolute path → used as-is (dirfd ignored, like Linux).
    //   - relative path → resolved against the dirfd's recorded open path.
    let resolved: Option<alloc::string::String> = if path_str.is_empty() {
        if (a.arg4 & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
            fd_path_for_task(task, dirfd as u32)
        } else {
            None
        }
    } else if path_str.starts_with('/') {
        Some(path_str)
    } else if dirfd >= 0 {
        fd_path_for_task(task, dirfd as u32).map(|mut d| {
            if !d.ends_with('/') {
                d.push('/');
            }
            d.push_str(&path_str);
            d
        })
    } else {
        // AT_FDCWD (or no dir): treat as a plain (cwd-relative) execve path.
        Some(path_str)
    };

    if let Some(p) = resolved {
        do_execve_resolved(ctx, p, a.arg2, a.arg3, None);
        return;
    }

    // No filesystem path for the fd. For an AT_EMPTY_PATH fexecve this is the
    // memfd case (systemd seals its sd-executor into a memfd and fexecve's it):
    // read the ELF straight out of the fd's FileOps and exec those bytes.
    if path_empty && (a.arg4 & AT_EMPTY_PATH) != 0 && dirfd >= 0 {
        if let Some(bytes) = read_fd_image(task, dirfd as u32) {
            let label = alloc::format!("/proc/self/fd/{}", dirfd);
            do_execve_resolved(ctx, label, a.arg2, a.arg3, Some(bytes));
            return;
        }
    }
    // Bad dirfd / unreadable fd — ENOENT.
    ctx.set_return(SyscallReturn::ok((-2i64) as u64));
}
