#[allow(unused_imports)]
use super::*;

/// `fs/statfs.c::fd_statfs`:
///
/// ```text
///   CLASS(fd_raw, f)(fd);
///   if (fd_empty(f)) return -EBADF;       /* O_PATH is fine: fd_raw */
///   error = vfs_statfs(&fd_file(f)->f_path, st);
///   ... then copy_to_user(buf)            /* -EFAULT */
/// ```
///
/// An unopened descriptor used to fall through to the "/" fallback below and
/// report SUCCESS with the root filesystem's numbers; a bad buffer was the
/// `-1` sentinel (EPERM).
pub(crate) fn sys_fstatfs(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1;
    let task = current_task_id();
    if fd::with_table(task, |t| t.get(fd).is_some()) != Some(true) {
        ctx.set_return(errno_ret(EBADF));
        return;
    }
    // Report the statfs of the filesystem backing THIS fd (not a synthetic
    // "/"). The per-fd backing path recorded at open() maps back to its mount,
    // whose super-magic `fill_statfs_for_path` derives. sd-device's
    // `fd_is_fs_type(fd, SYSFS_MAGIC)` fstatfs()es an opened /sys/... device
    // node and rejects it ("outside of sysfs") unless f_type == SYSFS_MAGIC —
    // so a synthetic "/" answer (ext2/tmpfs magic) broke every udev device
    // lookup. Fall back to "/" for fds with no path (pipes, sockets, eventfd).
    let path = fd_path_for_task(task, fd)
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| alloc::string::String::from("/"));
    match fill_statfs_for_path(&path, buf_ptr) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(errno) => ctx.set_return(errno_ret(errno)),
    }
}
