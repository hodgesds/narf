#[allow(unused_imports)]
use super::*;

/// `ftruncate(fd, length)` with `fs/open.c::do_sys_ftruncate` error ordering:
///
/// ```text
///   if (length < 0) return -EINVAL;
///   f = fdget(fd); if (!fd_file(f)) return -EBADF;
///   error = -EINVAL;
///   if (!S_ISREG(inode->i_mode) || !(f->f_mode & FMODE_WRITE)) goto out;
/// ```
///
/// Failures used to collapse into the `-1` sentinel, so a caller that
/// ftruncate'd a closed descriptor saw EPERM instead of EBADF — the shape
/// glibc's `ftruncate` reports verbatim.
pub(crate) fn sys_ftruncate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let len = args.arg1;
    let task = current_task_id();

    // off_t is signed; a negative length never reaches the fd table.
    if (len as i64) < 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    // Both "not a regular file" and "not opened for writing" are -EINVAL
    // here, not -EBADF: `do_sys_ftruncate` has already accepted the fd.
    if endpoint.ops.stat().mode.file_type != narf_filesystem::FileType::File
        || !endpoint.writable()
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    match poll_blocking(endpoint.ops.truncate(len)) {
        Some(Ok(())) => {
            // inotify: truncate changes file content → IN_MODIFY.
            #[cfg(feature = "linux-compat")]
            crate::mqueue::notify_modify_fd(task, fd);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Err(error)) => ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64)),
        // A truncate future that cannot resolve in trap context is an I/O
        // failure, not a caller error.
        None => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
    }
}
