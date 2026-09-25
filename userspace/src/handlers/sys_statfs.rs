#[allow(unused_imports)]
use super::*;

/// `fs/statfs.c::user_statfs`:
///
/// ```text
///   error = user_path_at(AT_FDCWD, pathname, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &path);
///   if (!error) error = vfs_statfs(&path, st);
///   ... then copy_to_user(buf)                       /* -EFAULT */
/// ```
///
/// The path is looked up before anything else, so a missing name is -ENOENT
/// (a non-directory prefix -ENOTDIR, an unsearchable one -EACCES) and a bad
/// `buf` is -EFAULT only for a path that resolved. This used to report
/// success for ANY path under a mount — `statfs("/no/such")` returned the
/// covering filesystem's numbers — and the `-1` sentinel (EPERM) for a bad
/// buffer.
pub(crate) fn sys_statfs(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux: statfs(const char *path, struct statfs *buf). arg0 = NUL-term
    // path, arg1 = buf. (Was NARF-native (path_ptr, path_len, buf).)
    let path = match copy_user_cstr_checked(args.arg0, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if let Err(errno) = user_path_lookup(current_task_id(), -100, &path, true, false) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    match fill_statfs_for_path(&path, args.arg1) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(errno) => ctx.set_return(errno_ret(errno)),
    }
}
