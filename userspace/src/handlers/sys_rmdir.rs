#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_rmdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    // `getname()` (fs/namei.c): -EFAULT for an unreadable pointer,
    // -ENAMETOOLONG for a path that reaches PATH_MAX with no terminator.
    // Both used to take the shared `fail` sentinel, which reaches libc as
    // errno 1 (EPERM) — an answer that says "you may not do this" about a
    // caller whose only mistake was a bad pointer or an over-long name.
    let path = match copy_user_cstr_checked(ptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    let path = resolve_cwd_path(current_task_id(), &path);
    rmdir_absolute(ctx, &path);
}

/// `rmdir` on an ALREADY-absolute path, so `sys_unlinkat(AT_REMOVEDIR)` can
/// resolve against its dirfd first and share this body.
pub(crate) fn rmdir_absolute(ctx: &mut dyn TrapContext, path: &str) {
    let outcome = current_resolve_parent_absolute(path, |_fs, parent, leaf| {
        poll_blocking(parent.rmdir(leaf))
    });
    match outcome {
        Some(Some(Ok(()))) => {
            crate::mqueue::notify_delete(path, true);
            ctx.set_return(SyscallReturn::ok(0));
        }
        // The parent filesystem resolved but rmdir reported an error — map it
        // to the precise Linux errno (ENOENT / ENOTEMPTY / ENOTDIR / …) so a
        // bare -1 → EPERM never surfaces (that aborted systemd's mount-
        // teardown rmdir of /run/systemd/propagate/<unit>).
        Some(Some(Err(e))) => ctx.set_return(SyscallReturn::ok(rmdir_errno(e))),
        // The parent path/filesystem didn't resolve, or the async poll never
        // completed → the target directory can't exist. Linux: ENOENT.
        _ => ctx.set_return(SyscallReturn::ok((-2i64) as u64)), // -ENOENT
    }
}
