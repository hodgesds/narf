#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_rename(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let old_ptr = args.arg0;
    let new_ptr = args.arg1;
    // An unreadable user path pointer is EFAULT, not a bare -1 → EPERM.
    let old_path = match copy_user_cstr_checked(old_ptr, 4096) {
            Ok(s) => s,
            Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
            }
        };
    let new_path = match copy_user_cstr_checked(new_ptr, 4096) {
            Ok(s) => s,
            Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
            }
        };
    let task = current_task_id();
    let old_path = resolve_cwd_path(task, &old_path);
    let new_path = resolve_cwd_path(task, &new_path);
    rename_absolute(ctx, &old_path, &new_path);
}

/// Rename with both paths ALREADY resolved to absolute.
///
/// Split out of `sys_rename` so `sys_renameat` can join its relative paths
/// against the caller's dirfds and then share this body. `sys_renameat`
/// previously proxied to `sys_rename` by handing over the raw user pointers,
/// which forced the paths through `resolve_cwd_path` and silently discarded
/// the dirfds — see `smoke_abi_fsx_renameat_honours_dirfd`.
pub(crate) fn rename_absolute(ctx: &mut dyn TrapContext, old_path: &str, new_path: &str) {
    // Both paths must split into the same parent directory — cross-
    // directory rename isn't supported by the DirOps surface today
    // (would need a registry-aware version that locks both parents).
    // A relative path with no slash is a malformed absolute path here → EINVAL.
    let old_split = match old_path.rfind('/') {
        Some(i) => i,
        None => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
    };
    let new_split = match new_path.rfind('/') {
        Some(i) => i,
        None => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
    };
    if old_path[..old_split] != new_path[..new_split] {
        // Different parent directories. That is only EXDEV when the two
        // parents are on different MOUNTS — within one filesystem Linux
        // moves the name, and real software depends on it: Qt's
        // QSaveFile (so every KDE/KConfig/KSycoca write) stages into a
        // temp file and renames it onto the target, and when the staging
        // file lands in a different directory a blanket EXDEV surfaces to
        // the user as "Invalid cross-device link" / "Disk full?" and the
        // config or cache is never written.
        ctx.set_return(SyscallReturn::ok(cross_dir_rename(old_path, new_path)));
        return;
    }
    let new_leaf = &new_path[new_split + 1..];
    // `do_renameat2` -> `may_delete(old_dir, old_dentry, ..)` for the name
    // being taken away, and the same again for a destination that already
    // exists and is about to be replaced. Both live in this one directory
    // (a differing parent took the `cross_dir_rename` path above), so both
    // are checked inside the single resolution below. The sticky rule
    // applies to each victim separately: moving ANOTHER user's file out of
    // /tmp is exactly what S_ISVTX forbids.
    // A rename writes BOTH directories, so both mounts must be writable.
    if let Err(errno) = mnt_want_write(old_path).and_then(|()| mnt_want_write(new_path)) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    let task = current_task_id();
    let mut refused = None;
    let outcome = current_resolve_parent_absolute(old_path, |_fs, parent, old_leaf| {
        for leaf in [old_leaf, new_leaf] {
            if let Some((victim_uid, victim_gid)) = entry_owner(&*parent, leaf) {
                if let Err(errno) = may_delete_in(&*parent, victim_uid, victim_gid, task) {
                    refused = Some(errno);
                    return None;
                }
            }
        }
        poll_blocking(parent.rename(old_leaf, new_leaf))
    });
    if let Some(errno) = refused {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    match outcome {
        Some(Some(Ok(()))) => {
            // inotify: paired IN_MOVED_FROM/IN_MOVED_TO sharing a cookie.
            crate::mqueue::notify_moved(old_path, new_path);
            ctx.set_return(SyscallReturn::ok(0));
        }
        // Parent resolved but rename failed → precise errno (ENOENT for a
        // missing source, …) instead of a bare -1 → EPERM. systemd renames
        // /run/systemd/propagate/<unit> dirs during mount teardown and a
        // spurious EPERM there aborts the unit.
        Some(Some(Err(e))) => ctx.set_return(SyscallReturn::ok(rename_errno(e))),
        // Parent path/filesystem didn't resolve → source can't exist: ENOENT.
        _ => ctx.set_return(SyscallReturn::ok((-2i64) as u64)), // -ENOENT
    }
}
