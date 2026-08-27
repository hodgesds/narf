#[allow(unused_imports)]
use super::*;

/// `truncate(path, length)` with `fs/open.c::do_sys_truncate` errno shape:
///
/// ```text
///   if (length < 0) return -EINVAL;
///   error = user_path_at(...);            /* -ENOENT / -ENOTDIR / -EACCES */
///   if (S_ISDIR(inode->i_mode)) goto out;         /* -EISDIR */
///   if (!S_ISREG(inode->i_mode)) goto out;        /* -EINVAL */
/// ```
///
/// Every one of those used to be the `-1` sentinel, which userspace decodes
/// as EPERM. `truncate("/does/not/exist", 0)` reporting "Operation not
/// permitted" instead of ENOENT defeats the standard create-if-missing
/// fallback, so each case now carries its own errno.
pub(crate) fn sys_truncate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux: truncate(const char *path, off_t length). arg0 = NUL-terminated
    // path, arg1 = new length. (Was NARF-native (path_ptr, path_len, size).)
    let ptr = args.arg0;
    let new_size = args.arg1;

    if (new_size as i64) < 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let Some(path) = copy_user_cstr(ptr, 4096) else {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    };
    let path = apply_chroot(&path);
    let ops = narf_filesystem::registry()
        .resolve_absolute(&path, |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    let Some(ops) = ops else {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
        return;
    };
    // A directory is EISDIR; any other non-regular target (fifo, socket,
    // device node) is EINVAL — truncation is only defined for regular files.
    match ops.stat().mode.file_type {
        narf_filesystem::FileType::File => {}
        narf_filesystem::FileType::Dir => {
            ctx.set_return(SyscallReturn::ok((-21i64) as u64)); // -EISDIR
            return;
        }
        _ => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
    }
    match poll_blocking(ops.truncate(new_size)) {
        Some(Ok(())) => {
            // inotify: truncate changes file content → IN_MODIFY.
            crate::mqueue::notify_modify_path(&path);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Err(error)) => ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64)),
        None => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
    }
}
