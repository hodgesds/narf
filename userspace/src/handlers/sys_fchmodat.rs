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
        narf_filesystem::FsError::NotFound => -2, // -ENOENT
        narf_filesystem::FsError::PermissionDenied => -13, // -EACCES
        narf_filesystem::FsError::InvalidPath => -22, // -EINVAL
        narf_filesystem::FsError::NoSpace => -28, // -ENOSPC
        narf_filesystem::FsError::QuotaExceeded => -122, // -EDQUOT
        narf_filesystem::FsError::ReadOnly => -30, // -EROFS
        narf_filesystem::FsError::Unsupported => -95, // -EOPNOTSUPP
        _ => -5,                                  // -EIO
    }
}

fn fchmodat_common(ctx: &mut dyn TrapContext, flags: u64) {
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    const AT_EMPTY_PATH: u64 = 0x1000;

    if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    let args = *ctx.args();
    let raw = match copy_user_cstr_checked(args.arg1, 4096) {
            Ok(path) => path,
            Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64)); // -EFAULT
            return;
            }
        };

    if raw.is_empty() {
        if flags & AT_EMPTY_PATH != 0 {
            // Linux permits AT_FDCWD here as well: an empty path names cwd.
            if args.arg0 as i64 == -100 {
                let cwd = resolve_cwd_path(current_task_id(), ".");
                if let Some(dir) = resolve_dir_absolute(&cwd) {
                    match poll_blocking(dir.set_dir_mode_async((args.arg2 as u32 & 0o7777) as u16))
                    {
                        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
                        Some(Err(error)) => {
                            ctx.set_return(SyscallReturn::ok(metadata_errno(error) as u64));
                        }
                        None => ctx.set_return(SyscallReturn::ok((-5i64) as u64)),
                    }
                } else {
                    ctx.set_return(SyscallReturn::ok((-2i64) as u64));
                }
            } else if args.arg0 as i64 >= 0 {
                let proxy_args = SyscallArgs {
                    arg0: args.arg0,
                    arg1: args.arg2,
                    arg2: 0,
                    arg3: 0,
                    arg4: 0,
                    arg5: 0,
                };
                let mut proxy = ArgReshape {
                    inner: ctx,
                    args: proxy_args,
                };
                sys_fchmod(&mut proxy);
            } else {
                ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            }
        } else {
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
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
    let mode = (args.arg2 as u32 & 0o7777) as u16;
    let follow_final = flags & AT_SYMLINK_NOFOLLOW == 0;

    // Follow a final symlink by default, exactly as Linux's LOOKUP_FOLLOW
    // path does. Ext2 also exposes directories through FileOps, so this arm
    // intentionally precedes the dir-only fallback.
    if let Some(file) = resolve_file_absolute_ext(&path, follow_final) {
        match poll_blocking(file.set_perms(mode)) {
            Some(Ok(())) => {
                crate::mqueue::notify_attrib(&path, file.as_dir().is_some());
                ctx.set_return(SyscallReturn::ok(0));
            }
            Some(Err(error)) => {
                ctx.set_return(SyscallReturn::ok(metadata_errno(error) as u64));
            }
            None => ctx.set_return(SyscallReturn::ok((-5i64) as u64)),
        }
        return;
    }

    // MemFs represents directories only through DirOps, so direct directory
    // paths take this fallback after the file/symlink resolver.
    if let Some(dir) = resolve_dir_absolute(&path) {
        match poll_blocking(dir.set_dir_mode_async(mode)) {
            Some(Ok(())) => {
                crate::mqueue::notify_attrib(&path, true);
                ctx.set_return(SyscallReturn::ok(0));
            }
            Some(Err(error)) => {
                ctx.set_return(SyscallReturn::ok(metadata_errno(error) as u64));
            }
            None => ctx.set_return(SyscallReturn::ok((-5i64) as u64)),
        }
        return;
    }

    ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
}
