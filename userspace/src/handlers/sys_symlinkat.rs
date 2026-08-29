#[allow(unused_imports)]
use super::*;

/// `symlinkat(target, newdirfd, linkpath)`.
///
/// `newdirfd` was previously DISCARDED (`let _dirfd = args.arg1;`) and this
/// proxied to `sys_symlink` with the raw pointers, so a relative linkpath
/// was created relative to the CWD instead of the named directory.
///
/// udev creates every `/dev/` alias this way (by-id, by-path, by-uuid) from
/// a directory fd, so an ignored dirfd puts the link in the wrong place —
/// or fails — and the alias never appears.
///
/// Only the LINK PATH is resolved. A symlink target may legitimately be
/// relative and is stored verbatim, exactly as Linux does.
pub(crate) fn sys_symlinkat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux: symlinkat(const char *target, int newdirfd, const char *linkpath).
    let target_ptr = args.arg0;
    let newdirfd = args.arg1 as i64;
    let link_ptr = args.arg2;
    let target_str = match copy_user_cstr_checked(target_ptr, 4096) {
            Ok(s) => s,
            Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
            }
        };
    let link_str = match copy_user_cstr_checked(link_ptr, 4096) {
            Ok(s) => s,
            Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
            }
        };
    let task = current_task_id();
    let joined = match resolve_at_path(task, newdirfd, &link_str) {
        Ok(p) => p,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok(e as u64));
            return;
        }
    };
    let link_path = resolve_cwd_path(task, &joined);
    symlink_absolute(ctx, &target_str, &link_path);
}
