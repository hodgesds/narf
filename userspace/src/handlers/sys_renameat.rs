#[allow(unused_imports)]
use super::*;

/// Resolve one `*at()` path against its dirfd, POSIX-style.
///
/// Mirrors `sys_openat`: an absolute path or `AT_FDCWD` resolves as usual; a
/// relative path is joined onto the directory backing `dirfd`. Returns the
/// errno to report when the descriptor cannot name a directory — Linux gives
/// EBADF there, and resolving from the cwd instead would silently operate on
/// a same-named file in the WRONG directory, which is worse than an error.
pub(crate) fn resolve_at(dirfd: i64, path: &str, task: u64) -> Result<alloc::string::String, i64> {
    const AT_FDCWD: i64 = -100;
    if path.starts_with('/') || dirfd == AT_FDCWD {
        return Ok(alloc::string::String::from(path));
    }
    if dirfd < 0 {
        return Err(-9); // EBADF — AT_FDCWD is the only negative dirfd accepted
    }
    match fd_path_for_task(task, dirfd as u32) {
        Some(dir) if dir.starts_with('/') => Ok(alloc::format!(
            "{}/{}",
            dir.trim_end_matches('/'),
            path
        )),
        _ => Err(-9), // EBADF
    }
}

/// `renameat(olddirfd, oldpath, newdirfd, newpath)`.
///
/// Both dirfds are load-bearing and were previously DISCARDED
/// (`let _old_dirfd = args.arg0;`): this proxied to `sys_rename` with the raw
/// user pointers, so relative paths went through `resolve_cwd_path` and
/// resolved against the CWD instead of the directories the caller named.
///
/// systemd-journald rotates the runtime journal with
/// `renameat(dir_fd, name, dir_fd, newname)` against a directory fd it
/// already holds (`journal_file_dispose()`), so on NARF the rotation failed
/// and the boot log carried "Failed to create new runtime journal: No such
/// file or directory" — after which no runtime journal exists and every
/// later `journalctl` reports "No journal files were opened".
///
/// Note the failure mode is not only "returns an error": with a relative path
/// that happens to exist under the cwd, ignoring the dirfd renames the WRONG
/// FILE and reports success.
pub(crate) fn sys_renameat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int renameat(int olddirfd, const char *oldpath,
    // int newdirfd, const char *newpath)`. Two cstrs, no lengths.
    let old_dirfd = args.arg0 as i64;
    let old_uptr = args.arg1;
    let new_dirfd = args.arg2 as i64;
    let new_uptr = args.arg3;

    let efault = SyscallReturn::ok((-14i64) as u64);
    let old_str = match copy_user_cstr(old_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(efault);
            return;
        }
    };
    let new_str = match copy_user_cstr(new_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(efault);
            return;
        }
    };

    let task = current_task_id();
    let old_path = match resolve_at(old_dirfd, &old_str, task) {
        Ok(p) => p,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok(e as u64));
            return;
        }
    };
    let new_path = match resolve_at(new_dirfd, &new_str, task) {
        Ok(p) => p,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok(e as u64));
            return;
        }
    };

    // Apply the caller's chroot exactly as `sys_rename` does for the cwd
    // form, so a chrooted process renames inside its own namespace.
    let old_path = resolve_cwd_path(task, &old_path);
    let new_path = resolve_cwd_path(task, &new_path);
    rename_absolute(ctx, &old_path, &new_path);
}
