#[allow(unused_imports)]
use super::*;

/// `unlinkat(dirfd, pathname, flags)`.
///
/// The dirfd was previously DISCARDED (`let _dirfd = args.arg0;`): this
/// proxied to `sys_unlink` / `sys_rmdir` with the raw user pointer, so a
/// relative path resolved against the CWD instead of the directory the
/// caller named.
///
/// That is not a benign approximation. systemd-journald removes rotated
/// journals with `unlinkat(dir_fd, name, 0)` against a directory fd it
/// holds, and systemd-tmpfiles prunes trees the same way. With the dirfd
/// ignored the call either fails or — with a same-named file under the cwd
/// — DELETES THE WRONG FILE and reports success.
pub(crate) fn sys_unlinkat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int unlinkat(int dirfd, const char *pathname,
    // int flags)`. arg2 is flags, not path_len.
    let dirfd = args.arg0 as i64;
    let path_uptr = args.arg1;
    let flags = args.arg2;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let task = current_task_id();
    let joined = match resolve_at(dirfd, &path_str, task) {
        Ok(p) => p,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok(e as u64));
            return;
        }
    };
    // Re-apply the caller's chroot exactly as the cwd form does.
    let path = resolve_cwd_path(task, &joined);
    if (flags & AT_REMOVEDIR) != 0 {
        rmdir_absolute(ctx, &path);
    } else {
        unlink_absolute(ctx, &path);
    }
}
