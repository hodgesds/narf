#[allow(unused_imports)]
use super::*;

fn chown_errno(error: narf_filesystem::FsError) -> i64 {
    match error {
        narf_filesystem::FsError::NotFound => ENOENT,
        narf_filesystem::FsError::PermissionDenied => EPERM,
        narf_filesystem::FsError::InvalidPath => EINVAL,
        narf_filesystem::FsError::NoSpace => ENOSPC,
        narf_filesystem::FsError::QuotaExceeded => EDQUOT,
        narf_filesystem::FsError::ReadOnly => EROFS,
        narf_filesystem::FsError::Unsupported => EOPNOTSUPP,
        _ => EIO,
    }
}

/// `fchownat(dirfd, path, uid, gid, flags)`.
pub(crate) fn sys_fchmodat_or_fchownat(ctx: &mut dyn TrapContext) {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;

    let args = *ctx.args();
    let flags = args.arg4;
    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let raw = match copy_user_cstr_checked(args.arg1, 4096) {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };

    if raw.is_empty() {
        if flags & AT_EMPTY_PATH == 0 {
            ctx.set_return(errno_ret(ENOENT));
            return;
        }
        let dirfd = args.arg0 as i32 as i64;
        if dirfd == -100 {
            let path = resolve_cwd_path(current_task_id(), ".");
            if let Some(dir) = resolve_dir_absolute(&path) {
                let (old_uid, old_gid) = dir.dir_owners();
                let uid = if args.arg2 as u32 == u32::MAX {
                    old_uid
                } else {
                    args.arg2 as u32
                };
                let gid = if args.arg3 as u32 == u32::MAX {
                    old_gid
                } else {
                    args.arg3 as u32
                };
                match poll_blocking(dir.set_dir_owners_async(uid, gid)) {
                    Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
                    Some(Err(error)) => {
                        ctx.set_return(errno_ret(chown_errno(error)))
                    }
                    None => ctx.set_return(errno_ret(EIO)),
                }
            } else {
                ctx.set_return(errno_ret(ENOENT));
            }
        } else if dirfd >= 0 {
            let proxy_args = SyscallArgs {
                arg0: args.arg0,
                arg1: args.arg2,
                arg2: args.arg3,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            };
            let mut proxy = ArgReshape {
                inner: ctx,
                args: proxy_args,
            };
            sys_fchown(&mut proxy);
        } else {
            ctx.set_return(errno_ret(EBADF));
        }
        return;
    }

    let task = current_task_id();
    let effective = match resolve_at_path(task, args.arg0 as i64, &raw) {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    let path = resolve_cwd_path(task, &effective);
    // `chown_common`'s caller does `mnt_want_write` first: an ownership
    // change is a write to the inode.
    if let Err(errno) = mnt_want_write(&path) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // `may_setattr` bars ATTR_UID/ATTR_GID on an immutable or append-only
    // inode.
    if path_inode_flags(&path) & narf_filesystem::FS_PRIVILEGED_FL != 0 {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    let follow_final = flags & AT_SYMLINK_NOFOLLOW == 0;
    let requested_uid = args.arg2 as u32;
    let requested_gid = args.arg3 as u32;

    if let Some(file) = resolve_file_absolute_ext(&path, follow_final) {
        let (old_uid, old_gid) = file.owners();
        let uid = if requested_uid == u32::MAX {
            old_uid
        } else {
            requested_uid
        };
        let gid = if requested_gid == u32::MAX {
            old_gid
        } else {
            requested_gid
        };
        match poll_blocking(file.set_owners(uid, gid)) {
            Some(Ok(())) => {
                crate::mqueue::notify_attrib(&path, file.as_dir().is_some());
                ctx.set_return(SyscallReturn::ok(0));
            }
            Some(Err(error)) => ctx.set_return(errno_ret(chown_errno(error))),
            None => ctx.set_return(errno_ret(EIO)),
        }
        return;
    }

    if let Some(dir) = resolve_dir_absolute(&path) {
        let (old_uid, old_gid) = dir.dir_owners();
        let uid = if requested_uid == u32::MAX {
            old_uid
        } else {
            requested_uid
        };
        let gid = if requested_gid == u32::MAX {
            old_gid
        } else {
            requested_gid
        };
        match poll_blocking(dir.set_dir_owners_async(uid, gid)) {
            Some(Ok(())) => {
                crate::mqueue::notify_attrib(&path, true);
                ctx.set_return(SyscallReturn::ok(0));
            }
            Some(Err(error)) => ctx.set_return(errno_ret(chown_errno(error))),
            None => ctx.set_return(errno_ret(EIO)),
        }
        return;
    }

    ctx.set_return(errno_ret(ENOENT));
}
