#[allow(unused_imports)]
use super::*;

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

    let old_str = match copy_user_cstr_checked(old_uptr, 4096) {
            Ok(s) => s,
            Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
            }
        };
    let new_str = match copy_user_cstr_checked(new_uptr, 4096) {
            Ok(s) => s,
            Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
            }
        };

    let task = current_task_id();
    let old_path = match resolve_at_path(task, old_dirfd, &old_str) {
        Ok(p) => p,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok(e as u64));
            return;
        }
    };
    let new_path = match resolve_at_path(task, new_dirfd, &new_str) {
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
