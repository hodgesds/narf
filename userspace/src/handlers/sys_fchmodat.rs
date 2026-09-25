#[allow(unused_imports)]
use super::*;

/// Legacy `fchmodat(dirfd, path, mode)` has no flags argument. Keeping this
/// entry point separate prevents an arbitrary fourth syscall register from
/// accidentally enabling `AT_EMPTY_PATH`.
pub(crate) fn sys_fchmodat(ctx: &mut dyn TrapContext) {
    fchmodat_common(ctx, 0);
}

/// `fchmodat2(dirfd, path, mode, flags)`.
pub(crate) fn sys_fchmodat2(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg3;
    fchmodat_common(ctx, flags);
}

fn metadata_errno(error: narf_filesystem::FsError) -> i64 {
    match error {
        narf_filesystem::FsError::NotFound => ENOENT,
        narf_filesystem::FsError::PermissionDenied => EACCES,
        narf_filesystem::FsError::InvalidPath => EINVAL,
        narf_filesystem::FsError::NoSpace => ENOSPC,
        narf_filesystem::FsError::QuotaExceeded => EDQUOT,
        narf_filesystem::FsError::ReadOnly => EROFS,
        narf_filesystem::FsError::Unsupported => EOPNOTSUPP,
        _ => EIO,
    }
}

fn fchmodat_common(ctx: &mut dyn TrapContext, flags: u64) {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;

    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    let args = *ctx.args();
    let raw = match copy_user_cstr_checked(args.arg1, 4096) {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let task = current_task_id();
    let mode = (args.arg2 as u32 & 0o7777) as u16;

    if raw.is_empty() {
        if flags & AT_EMPTY_PATH != 0 {
            // Linux permits AT_FDCWD here as well: an empty path names cwd.
            let dirfd = args.arg0 as i32 as i64;
            if dirfd == -100 {
                let cwd = resolve_cwd_path(task, ".");
                if let Some(dir) = resolve_dir_absolute(&cwd) {
                    chmod_dir(ctx, &cwd, dir, mode, task);
                } else {
                    ctx.set_return(errno_ret(ENOENT));
                }
            } else if dirfd >= 0 {
                // The descriptor is resolved as a PATH here, so an O_PATH
                // descriptor is fine (unlike `fchmod`'s `fdget`).
                fchmod_fd(ctx, dirfd as u32, args.arg2, true);
            } else {
                ctx.set_return(errno_ret(EBADF));
            }
        } else {
            ctx.set_return(errno_ret(ENOENT));
        }
        return;
    }

    let effective = match resolve_at_path(task, args.arg0 as i64, &raw) {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    let path = resolve_cwd_path(task, &effective);
    let follow_final = flags & AT_SYMLINK_NOFOLLOW == 0;

    // `do_fchmodat`: `user_path_at` first, so a missing name is ENOENT
    // (ENOTDIR for a file used as a directory) even on a read-only mount;
    // only then `chmod_common` -> `mnt_want_write` -> `notify_change`.
    //
    // Follow a final symlink by default, exactly as Linux's LOOKUP_FOLLOW
    // path does. Ext2 also exposes directories through FileOps, so this arm
    // intentionally precedes the dir-only fallback.
    if let Some(file) = resolve_file_absolute_ext(&path, follow_final) {
        // A mode change is a write to the inode: EROFS on a read-only mount.
        if let Err(errno) = mnt_want_write(&path) {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
        // `may_setattr` (an append-only file's PERMISSIONS are frozen too,
        // or the restriction could be lifted by re-permissioning it), then
        // fchmodat2's AT_SYMLINK_NOFOLLOW landing on a symlink (EOPNOTSUPP),
        // then the owner test.
        let (uid, gid) = file.owners();
        let is_symlink = file.stat().mode.file_type == narf_filesystem::FileType::Symlink;
        if let Err(errno) = chmod_setattr_check(task, file.inode_flags(), is_symlink, uid, gid) {
            ctx.set_return(errno_ret(errno));
            return;
        }
        match poll_blocking(file.set_perms(mode)) {
            Some(Ok(())) => {
                crate::mqueue::notify_attrib(&path, file.as_dir().is_some());
                ctx.set_return(SyscallReturn::ok(0));
            }
            Some(Err(error)) => {
                ctx.set_return(errno_ret(metadata_errno(error)));
            }
            None => ctx.set_return(errno_ret(EIO)),
        }
        return;
    }

    // MemFs represents directories only through DirOps, so direct directory
    // paths take this fallback after the file/symlink resolver.
    if let Some(dir) = resolve_dir_absolute(&path) {
        chmod_dir(ctx, &path, dir, mode, task);
        return;
    }

    ctx.set_return(errno_ret(path_lookup_errno(&path)));
}

/// `chmod_common` on a directory reached through `DirOps`.
fn chmod_dir(
    ctx: &mut dyn TrapContext,
    path: &str,
    dir: alloc::sync::Arc<dyn narf_filesystem::DirOps>,
    mode: u16,
    task: u64,
) {
    if let Err(errno) = mnt_want_write(path) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    let (uid, gid) = dir.dir_owners();
    if let Err(errno) = chmod_setattr_check(task, path_inode_flags(path), false, uid, gid) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    match poll_blocking(dir.set_dir_mode_async(mode)) {
        Some(Ok(())) => {
            crate::mqueue::notify_attrib(path, true);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Err(error)) => {
            ctx.set_return(errno_ret(metadata_errno(error)));
        }
        None => ctx.set_return(errno_ret(EIO)),
    }
}
