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
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // `do_renameat2` walks the OLD name (`filename_parentat`) before the new
    // name's `getname()` error is examined, and `getname()` rejects "" with
    // -ENOENT — so an empty old name outranks an unreadable new one.
    if old_path.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    let new_path = match copy_user_cstr_checked(new_ptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if new_path.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    let task = current_task_id();
    let old_last = LastComponent::of(&old_path);
    let new_last = LastComponent::of(&new_path);
    let old_path = resolve_cwd_path(task, &old_path);
    let new_path = resolve_cwd_path(task, &new_path);
    rename_absolute(ctx, &old_path, &new_path, old_last, new_last, 0);
}

/// `RENAME_NOREPLACE` / `RENAME_EXCHANGE` (include/uapi/linux/fs.h).
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

/// Rename with both paths ALREADY resolved to absolute.
///
/// Shared by `rename`, `renameat` and `renameat2` (which has validated
/// `flags` already). `old_last` / `new_last` describe the caller's RAW last
/// components, which the normalised paths no longer show.
///
/// `sys_renameat` previously proxied to `sys_rename` by handing over the raw
/// user pointers, which forced the paths through `resolve_cwd_path` and
/// silently discarded the dirfds — see `smoke_abi_fsx_renameat_honours_dirfd`.
pub(crate) fn rename_absolute(
    ctx: &mut dyn TrapContext,
    old_path: &str,
    new_path: &str,
    old_last: LastComponent,
    new_last: LastComponent,
    flags: u32,
) {
    let ret = rename_impl(old_path, new_path, old_last, new_last, flags);
    ctx.set_return(SyscallReturn::ok(ret as u64));
}

/// `fs/namei.c::do_renameat2` + `vfs_rename`, in their order. Returns 0 or a
/// negative errno.
///
/// Every step used to be decided by whichever backend call happened to fail
/// first, and the cross-directory path skipped the read-only and permission
/// checks entirely. The order that matters, all from `do_renameat2`:
///
/// ```text
/// filename_parentat(old), filename_parentat(new)  /* walk errors      */
/// if (old_path.mnt != new_path.mnt)     -EXDEV
/// if (old_type != LAST_NORM)            -EBUSY
/// if (new_type != LAST_NORM)            NOREPLACE ? -EEXIST : -EBUSY
/// mnt_want_write                        -EROFS
/// old dentry negative                   -ENOENT
/// NOREPLACE && new positive             -EEXIST
/// EXCHANGE && new negative              -ENOENT
/// !d_is_dir(old) && a trailing slash    -ENOTDIR
/// old is an ancestor of new             -EINVAL
/// new is an ancestor of old             EXCHANGE ? -EINVAL : -ENOTEMPTY
/// vfs_rename: source == target → 0; may_delete / may_create (EACCES,
///   sticky EPERM, immutable EPERM, then ENOTDIR / EISDIR); mountpoint EBUSY
/// ```
fn rename_impl(
    old_path: &str,
    new_path: &str,
    old_last: LastComponent,
    new_last: LastComponent,
    flags: u32,
) -> i64 {
    let exchange = flags & RENAME_EXCHANGE != 0;
    let noreplace = flags & RENAME_NOREPLACE != 0;
    let old_dir = match parentat_dir(old_path, old_last) {
        Ok(dir) => dir,
        Err(errno) => return errno,
    };
    let new_dir = match parentat_dir(new_path, new_last) {
        Ok(dir) => dir,
        Err(errno) => return errno,
    };
    if current_mount_id_at(&old_dir) != current_mount_id_at(&new_dir) {
        return -EXDEV;
    }
    // `.`, `..` or `/` as either last component. Lexical normalisation used
    // to turn `rename("d/.", "x")` into `rename("d", "x")` and move `d`.
    if !old_last.is_norm() {
        return -EBUSY;
    }
    if !new_last.is_norm() {
        return if noreplace { -EEXIST } else { -EBUSY };
    }
    // A rename writes BOTH directories; they share a mount (checked above).
    if let Err(errno) = mnt_want_write(old_path).and_then(|()| mnt_want_write(new_path)) {
        return errno;
    }
    let Some(old_is_dir) = namespace_node_kind(old_path) else {
        return -ENOENT;
    };
    let new_kind = namespace_node_kind(new_path);
    if noreplace && new_kind.is_some() {
        return -EEXIST;
    }
    if exchange && new_kind.is_none() {
        return -ENOENT;
    }
    // A trailing slash demands a directory. `rename("f", "x/")` used to
    // create `x`, and `rename("f/", "x")` to move the file.
    if !old_is_dir
        && (old_last == LastComponent::NormSlash
            || (!exchange && new_last == LastComponent::NormSlash))
    {
        return -ENOTDIR;
    }
    if exchange && new_kind == Some(false) && new_last == LastComponent::NormSlash {
        return -ENOTDIR;
    }
    if old_path == new_path {
        // `vfs_rename`: `if (source == target) return 0;`
        return 0;
    }
    // `lock_rename`'s trap: moving a directory under itself is EINVAL, and
    // a destination that is an ancestor of the source is (necessarily) a
    // non-empty directory. Nothing checked either for a cross-directory
    // move, which went straight to the backend.
    if old_is_dir && path_is_strictly_under(new_path, old_path) {
        return -EINVAL;
    }
    if new_kind == Some(true) && path_is_strictly_under(old_path, new_path) {
        return if exchange { -EINVAL } else { -ENOTEMPTY };
    }
    // `vfs_rename` -> `may_delete(old_dir, old)`, then `may_delete(new_dir,
    // new)` for a destination that exists or `may_create(new_dir)` for one
    // that does not: write+exec on each directory, plus the sticky rule for
    // each victim — moving ANOTHER user's file out of /tmp is exactly what
    // S_ISVTX forbids.
    let task = current_task_id();
    for (path, must_exist) in [(old_path, true), (new_path, new_kind.is_some())] {
        let verdict = current_resolve_parent_absolute(path, |_fs, parent, leaf| {
            match entry_owner(&*parent, leaf) {
                Some((uid, gid)) => may_delete_in(&*parent, uid, gid, task),
                None if must_exist => Ok(()),
                None => may_create_in(&*parent, task),
            }
        });
        if let Some(Err(errno)) = verdict {
            return errno;
        }
    }
    // `may_delete`: an immutable or append-only victim is -EPERM — renaming
    // it away is a removal.
    if path_inode_flags(old_path) & narf_filesystem::FS_PRIVILEGED_FL != 0
        || path_inode_flags(new_path) & narf_filesystem::FS_PRIVILEGED_FL != 0
    {
        return -EPERM;
    }
    // `may_delete_dentry` on the destination, with the SOURCE's type:
    // a directory may only replace a directory, and a non-directory only a
    // non-directory. RENAME_EXCHANGE checks each side against its own type,
    // so it has nothing to refuse here.
    if !exchange {
        match new_kind {
            Some(false) if old_is_dir => return -ENOTDIR,
            Some(true) if !old_is_dir => return -EISDIR,
            _ => {}
        }
    }
    // `vfs_rename`: `if (is_local_mountpoint(old_dentry) ||
    // is_local_mountpoint(new_dentry)) goto out (-EBUSY)`.
    if current_path_is_mount_root(old_path) || current_path_is_mount_root(new_path) {
        return -EBUSY;
    }

    if exchange {
        let outcome = current_resolve_two_parents_absolute(
            old_path,
            new_path,
            |_fs, old_parent, old_leaf, new_parent, new_leaf| {
                poll_blocking(old_parent.rename_to(
                    old_leaf,
                    &*new_parent,
                    new_leaf,
                    RENAME_EXCHANGE,
                ))
            },
        );
        return match outcome {
            Some(Some(Ok(()))) => {
                crate::mqueue::notify_moved(old_path, new_path);
                crate::mqueue::notify_moved(new_path, old_path);
                0
            }
            // A filesystem that cannot exchange answers EINVAL, as Linux's
            // `vfs_rename` does for a flag the backend does not implement.
            Some(Some(Err(narf_filesystem::FsError::Unsupported))) | Some(None) => -EINVAL,
            Some(Some(Err(e))) => rename_errno(e) as i64,
            None => -EXDEV,
        };
    }

    // Both paths must split into the same parent directory for
    // `DirOps::rename`; a differing parent goes through `cross_dir_rename`.
    // RENAME_NOREPLACE was decided above, so from here it is a plain rename.
    if parent_of_abs(old_path) != parent_of_abs(new_path) {
        // Different parent directories. That is only EXDEV when the two
        // parents are on different MOUNTS — within one filesystem Linux
        // moves the name, and real software depends on it: Qt's
        // QSaveFile (so every KDE/KConfig/KSycoca write) stages into a
        // temp file and renames it onto the target, and when the staging
        // file lands in a different directory a blanket EXDEV surfaces to
        // the user as "Invalid cross-device link" / "Disk full?" and the
        // config or cache is never written.
        return cross_dir_rename(old_path, new_path) as i64;
    }
    let new_leaf = match new_path.rfind('/') {
        Some(i) => &new_path[i + 1..],
        None => return -EINVAL,
    };
    let outcome = current_resolve_parent_absolute(old_path, |_fs, parent, old_leaf| {
        poll_blocking(parent.rename(old_leaf, new_leaf))
    });
    match outcome {
        Some(Some(Ok(()))) => {
            // inotify: paired IN_MOVED_FROM/IN_MOVED_TO sharing a cookie.
            crate::mqueue::notify_moved(old_path, new_path);
            0
        }
        // Report the filesystem's ACTUAL error. systemd's
        // `rename_noreplace()` retries via a link/unlink dance only on
        // EINVAL/ENOSYS/ENOTTY, and Linux answers EINVAL for a FLAG the
        // backend cannot perform — so a flagged rename a backend does not
        // implement is EINVAL, while a flagless one is `vfs_rename`'s
        // `if (!old_dir->i_op->rename) return -EPERM;`.
        Some(Some(Err(narf_filesystem::FsError::Unsupported))) if flags != 0 => -EINVAL,
        Some(Some(Err(e))) => rename_errno(e) as i64,
        // Parent path/filesystem didn't resolve → source can't exist: ENOENT.
        _ => -ENOENT,
    }
}
