#[allow(unused_imports)]
use super::*;

fn fd_ops(fd: u32) -> Option<alloc::sync::Arc<dyn narf_filesystem::FileOps>> {
    fd::with_table(current_task_id(), |table| {
        table.get(fd).map(|entry| entry.ops.clone())
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
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let Some(ops) = fd_ops(fd) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    let mode = (ctx.args().arg1 as u32 & 0o7777) as u16;
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
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let Some(ops) = fd_ops(fd) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    let (old_uid, old_gid) = ops.owners();
    let requested_uid = ctx.args().arg1 as u32;
    let requested_gid = ctx.args().arg2 as u32;
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
