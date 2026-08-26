#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_rmdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_cstr(ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
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
            #[cfg(feature = "linux-compat")]
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
