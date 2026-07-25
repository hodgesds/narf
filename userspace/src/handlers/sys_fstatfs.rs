#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fstatfs(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok(!0u64);
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1;
    // Report the statfs of the filesystem backing THIS fd (not a synthetic
    // "/"). The per-fd backing path recorded at open() maps back to its mount,
    // whose super-magic `fill_statfs_for_path` derives. sd-device's
    // `fd_is_fs_type(fd, SYSFS_MAGIC)` fstatfs()es an opened /sys/... device
    // node and rejects it ("outside of sysfs") unless f_type == SYSFS_MAGIC —
    // so a synthetic "/" answer (ext2/tmpfs magic) broke every udev device
    // lookup. Fall back to "/" for fds with no path (pipes, sockets, eventfd).
    let path = fd_path_of(current_task_id(), fd)
        .filter(|p| p.starts_with('/'))
        .unwrap_or_else(|| alloc::string::String::from("/"));
    if fill_statfs_for_path(&path, buf_ptr) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}
