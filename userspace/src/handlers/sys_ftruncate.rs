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
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // `fdget` refuses an O_PATH descriptor (FMODE_PATH) exactly as it does
    // an unopened slot, so O_PATH is -EBADF — not the -EINVAL a real but
    // read-only description gets below.
    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    // Both "not a regular file" and "not opened for writing" are -EINVAL
    // here, not -EBADF: `do_sys_ftruncate` has already accepted the fd.
    if endpoint.ops.stat().mode.file_type != narf_filesystem::FileType::File
        || !endpoint.writable()
    {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    // Truncation rewrites data, so BOTH flags refuse it: `do_ftruncate`
    // checks `IS_APPEND` (returning -EPERM) and reaches `notify_change`,
    // whose `may_setattr` bars an immutable or append-only inode from an
    // ATTR_SIZE change.
    if immutable_check(endpoint.ops.inode_flags(), true, false).is_err() {
        ctx.set_return(errno_ret(EPERM));
        return;
    }

    // `do_truncate` -> `notify_change` -> `inode_newsize_ok`: RLIMIT_FSIZE
    // bounds a truncate that GROWS the file. Shrinking is always allowed,
    // including from above the limit — that is how a process gets back under
    // one it has just lowered.
    if let Err(errno) = fsize_check_resize(task, endpoint.ops.stat().size, len) {
        ctx.set_return(errno_ret(errno));
        return;
    }

    // `do_truncate` passes `ATTR_KILL_SUID | ATTR_KILL_SGID` alongside the
    // size change, for the same reason a write does.
    file_remove_privs(endpoint.ops.as_ref(), task);

    match poll_blocking(endpoint.ops.truncate(len)) {
        Some(Ok(())) => {
            // inotify: truncate changes file content → IN_MODIFY.
            crate::mqueue::notify_modify_fd(task, fd);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Err(error)) => ctx.set_return(errno_ret(copy_fs_errno(error))),
        // A truncate future that cannot resolve in trap context is an I/O
        // failure, not a caller error.
        None => ctx.set_return(errno_ret(EIO)),
    }
}
