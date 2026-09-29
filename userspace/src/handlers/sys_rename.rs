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
/// One side of a rename, resolved ONCE: the parent directory handle, the
/// leaf name under it, and the child entry probed through that parent.
///
/// `rename_impl` used to answer every question about a path with a fresh
/// full-path resolution — `parentat_dir`, `namespace_node_kind`,
/// `entry_owner`, `path_inode_flags` and the backend rename each walked
/// the same components again, 12+ walks per rename, leaving the actual
/// `DirOps::rename` under 10% of the syscall's cycles. The probe keeps
/// `do_renameat2`'s check ORDER (documented above `rename_impl`) while
/// sourcing kind/owner/flags and the backend call from one resolution.
struct RenameSide {
    parent: alloc::sync::Arc<dyn narf_filesystem::DirOps>,
    leaf: alloc::string::String,
    /// File-shaped child (regular file, symlink, device node, or a
    /// synthetic FS's directory-typed marker), when the leaf has one.
    node: Option<alloc::sync::Arc<dyn narf_filesystem::FileOps>>,
    /// Directory-shaped child.
    subdir: Option<alloc::sync::Arc<dyn narf_filesystem::DirOps>>,
}

impl RenameSide {
    fn exists(&self) -> bool {
        self.node.is_some() || self.subdir.is_some()
    }
    fn is_dir(&self) -> bool {
        self.subdir.is_some()
            || self.node.as_ref().is_some_and(|n| {
                n.stat().mode.file_type == narf_filesystem::FileType::Dir
            })
    }
    /// `entry_owner`'s answer from the already-probed child: file-shaped
    /// owners first, then the directory's.
    fn owner(&self) -> Option<(u32, u32)> {
        if let Some(node) = &self.node {
            return Some(node.owners());
        }
        self.subdir.as_ref().map(|d| d.dir_owners())
    }
}

/// Probe `path`'s parent and leaf in a single resolution. `None` means the
/// parent walk failed (missing component or a non-directory on the way);
/// the caller classifies that with `path_lookup_errno` exactly as
/// `parentat_dir` did.
fn probe_rename_side(path: &str) -> Option<RenameSide> {
    current_resolve_parent_absolute(path, |_fs, parent, leaf| {
        // Sync lookup first (memfs and the synthetic FSes answer it);
        // the async form covers block-backed filesystems whose sync
        // lookup is stubbed. Mirrors `entry_owner`'s probe order.
        let node = parent
            .lookup(leaf)
            .or_else(|| poll_blocking(parent.lookup_async(leaf)).and_then(|r| r.ok()));
        let node_is_dir_marker = node.as_ref().is_some_and(|n| {
            n.stat().mode.file_type == narf_filesystem::FileType::Dir
        });
        let subdir = if node.is_none() || node_is_dir_marker {
            parent
                .lookup_dir(leaf)
                .or_else(|| poll_blocking(parent.lookup_dir_async(leaf)).and_then(|r| r.ok()))
        } else {
            None
        };
        RenameSide {
            leaf: alloc::string::String::from(leaf),
            parent,
            node,
            subdir,
        }
    })
}

/// `filename_parentat` for one rename side: the parent directory's PATH
/// (lexical for a LAST_NORM leaf, the path itself for `.`/`..`) plus the
/// probe when the leaf is LAST_NORM. A failed parent walk is classified
/// through `path_lookup_errno`, matching `parentat_dir`.
fn rename_walk_parent(
    path: &str,
    last: LastComponent,
) -> Result<(alloc::string::String, Option<RenameSide>), i64> {
    match last {
        LastComponent::Root => Ok((alloc::string::String::from("/"), None)),
        LastComponent::Dot | LastComponent::DotDot => {
            // The walk goes THROUGH the named directory, so the path
            // itself must resolve as one (its leaf is rejected with
            // EBUSY right after the EXDEV check, so no probe is needed).
            if stat_ino_path_dir_aware(path)
                .is_some_and(|(st, ..)| st.mode.file_type == narf_filesystem::FileType::Dir)
            {
                Ok((alloc::string::String::from(path), None))
            } else {
                Err(-path_lookup_errno(&alloc::format!("{path}/.")))
            }
        }
        _ => {
            let dir = parent_of_abs(path);
            match probe_rename_side(path) {
                Some(side) => Ok((alloc::string::String::from(dir), Some(side))),
                None => Err(-path_lookup_errno(&alloc::format!("{dir}/."))),
            }
        }
    }
}

/// `namespace_node_kind` from the probe: `Some(is_dir)` for an existing
/// leaf. A leaf that the parent does not list can still exist as a MOUNT
/// ROOT (the mount table, not the parent directory, makes it a directory)
/// — the one case the per-parent probe cannot see.
fn rename_side_kind(path: &str, side: &RenameSide) -> Option<bool> {
    if side.exists() {
        return Some(side.is_dir());
    }
    if current_path_is_mount_root(path) {
        return Some(true);
    }
    None
}

/// `path_inode_flags` from the probe. A symlink's flags come from its
/// TARGET (the file resolver follows the final link) and a directory
/// answered through the file-shaped resolver — both keep the original
/// helper; the overwhelmingly common regular-file leaf answers from the
/// probed node directly.
fn rename_side_inode_flags(path: &str, side: &RenameSide) -> u32 {
    match &side.node {
        Some(node) if node.stat().mode.file_type != narf_filesystem::FileType::Symlink => {
            node.inode_flags()
        }
        Some(_) => path_inode_flags(path),
        None if side.subdir.is_some() => path_inode_flags(path),
        None => 0,
    }
}

fn rename_impl(
    old_path: &str,
    new_path: &str,
    old_last: LastComponent,
    new_last: LastComponent,
    flags: u32,
) -> i64 {
    let exchange = flags & RENAME_EXCHANGE != 0;
    let noreplace = flags & RENAME_NOREPLACE != 0;
    let (old_dir, old_probe) = match rename_walk_parent(old_path, old_last) {
        Ok(walked) => walked,
        Err(errno) => return errno,
    };
    let (new_dir, new_probe) = match rename_walk_parent(new_path, new_last) {
        Ok(walked) => walked,
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
    // Both lasts are LAST_NORM from here, so both sides carry a probe.
    let Some(old_side) = old_probe else {
        return -ENOENT;
    };
    let Some(new_side) = new_probe else {
        return -ENOENT;
    };
    // A rename writes BOTH directories; they share a mount (checked above).
    if let Err(errno) = mnt_want_write(old_path).and_then(|()| mnt_want_write(new_path)) {
        return errno;
    }
    let Some(old_is_dir) = rename_side_kind(old_path, &old_side) else {
        return -ENOENT;
    };
    let new_kind = rename_side_kind(new_path, &new_side);
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
    for (side, must_exist) in [(&old_side, true), (&new_side, new_kind.is_some())] {
        let verdict = match side.owner() {
            Some((uid, gid)) => may_delete_in(&*side.parent, uid, gid, task),
            None if must_exist => Ok(()),
            None => may_create_in(&*side.parent, task),
        };
        if let Err(errno) = verdict {
            return errno;
        }
    }
    // `may_delete`: an immutable or append-only victim is -EPERM — renaming
    // it away is a removal.
    if rename_side_inode_flags(old_path, &old_side) & narf_filesystem::FS_PRIVILEGED_FL != 0
        || rename_side_inode_flags(new_path, &new_side) & narf_filesystem::FS_PRIVILEGED_FL != 0
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
        // The parents are already in hand (same-mount was established by
        // the EXDEV check above, which is all `resolve_two_parents` added).
        let outcome = poll_blocking(old_side.parent.rename_to(
            &old_side.leaf,
            &*new_side.parent,
            &new_side.leaf,
            RENAME_EXCHANGE,
        ));
        return match outcome {
            Some(Ok(())) => {
                crate::mqueue::notify_moved(old_path, new_path);
                crate::mqueue::notify_moved(new_path, old_path);
                0
            }
            // A filesystem that cannot exchange answers EINVAL, as Linux's
            // `vfs_rename` does for a flag the backend does not implement.
            Some(Err(narf_filesystem::FsError::Unsupported)) | None => -EINVAL,
            Some(Err(e)) => rename_errno(e) as i64,
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
    let outcome = poll_blocking(old_side.parent.rename(&old_side.leaf, &new_side.leaf));
    match outcome {
        Some(Ok(())) => {
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
        Some(Err(narf_filesystem::FsError::Unsupported)) if flags != 0 => -EINVAL,
        Some(Err(e)) => rename_errno(e) as i64,
        // The backend never completed the future — treat as the source
        // having vanished, as the old parent-re-resolution path did.
        None => -ENOENT,
    }
}
