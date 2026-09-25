#[allow(unused_imports)]
use super::*;

/// The open file behind `fd`, or `None` when there is none.
///
/// `allow_path` selects between Linux's two descriptor lookups: `fchmod` /
/// `fchown` use `fdget`, which does not hand out O_PATH files (-EBADF),
/// while the `AT_EMPTY_PATH` arm of `fchmodat2` / `fchownat` resolves the
/// descriptor as a path and accepts them (probed on Linux 6.18).
fn fd_ops(fd: u32, allow_path: bool) -> Option<alloc::sync::Arc<dyn narf_filesystem::FileOps>> {
    fd::with_table(current_task_id(), |table| {
        let entry = table.get(fd)?;
        if !allow_path && table.status_flags(fd).unwrap_or(0) & crate::fd::O_PATH != 0 {
            return None;
        }
        Some(entry.ops.clone())
    })
    .flatten()
}

fn fd_metadata_errno(error: narf_filesystem::FsError, chown: bool) -> i64 {
    match error {
        narf_filesystem::FsError::PermissionDenied if chown => EPERM,
        narf_filesystem::FsError::PermissionDenied => EACCES,
        narf_filesystem::FsError::InvalidPath => EINVAL,
        narf_filesystem::FsError::NoSpace => ENOSPC,
        narf_filesystem::FsError::QuotaExceeded => EDQUOT,
        narf_filesystem::FsError::ReadOnly => EROFS,
        narf_filesystem::FsError::Unsupported => EOPNOTSUPP,
        _ => EIO,
    }
}

pub(crate) fn sys_fchmod(ctx: &mut dyn TrapContext) {
    let (fd, mode) = (ctx.args().arg0 as u32, ctx.args().arg1);
    fchmod_fd(ctx, fd, mode, false);
}

/// `chmod_common` on the file behind a descriptor. Shared by `fchmod` and
/// the `AT_EMPTY_PATH` arm of `fchmodat2`.
pub(crate) fn fchmod_fd(ctx: &mut dyn TrapContext, fd: u32, mode: u64, allow_path: bool) {
    let task = current_task_id();
    let Some(ops) = fd_ops(fd, allow_path) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    let (uid, gid) = ops.owners();
    let is_symlink = ops.stat().mode.file_type == narf_filesystem::FileType::Symlink;
    if let Err(errno) = chmod_setattr_check(task, ops.inode_flags(), is_symlink, uid, gid) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    let mode = (mode as u32 & 0o7777) as u16;
    match poll_blocking(ops.set_perms(mode)) {
        Some(Ok(())) => {
            crate::mqueue::notify_attrib_fd(task, fd);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Err(error)) => {
            ctx.set_return(errno_ret(fd_metadata_errno(error, false)));
        }
        None => ctx.set_return(errno_ret(EIO)),
    }
}

pub(crate) fn sys_fchown(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    fchown_fd(ctx, a.arg0 as u32, a.arg1 as u32, a.arg2 as u32, false);
}

/// `chown_common` on the file behind a descriptor. Shared by `fchown` and
/// the `AT_EMPTY_PATH` arm of `fchownat`.
pub(crate) fn fchown_fd(
    ctx: &mut dyn TrapContext,
    fd: u32,
    requested_uid: u32,
    requested_gid: u32,
    allow_path: bool,
) {
    let task = current_task_id();
    let Some(ops) = fd_ops(fd, allow_path) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    let (old_uid, old_gid) = ops.owners();
    if let Err(errno) = chown_setattr_check(
        task,
        ops.inode_flags(),
        old_uid,
        old_gid,
        requested_uid,
        requested_gid,
    ) {
        ctx.set_return(errno_ret(errno));
        return;
    }
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
    match poll_blocking(ops.set_owners(uid, gid)) {
        Some(Ok(())) => {
            crate::mqueue::notify_attrib_fd(task, fd);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Err(error)) => {
            ctx.set_return(errno_ret(fd_metadata_errno(error, true)));
        }
        None => ctx.set_return(errno_ret(EIO)),
    }
}
