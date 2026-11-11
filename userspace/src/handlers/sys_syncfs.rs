#[allow(unused_imports)]
use super::*;

/// `syncfs(fd)` — flush the filesystem backing `fd`.
pub(crate) fn sys_syncfs(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    // `CLASS(fd, f)(fd)`: an unopened slot or an O_PATH description → -EBADF.
    let Some(ops) = copy_fd_endpoint(task, fd).map(|e| e.ops) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    // `sync_filesystem` → `writeback_inodes_sb`: every dirty `MAP_SHARED`
    // page of every file on this filesystem first, whether or not anything
    // still has the file open — the filesystem's own syncfs walk cannot see
    // the file cache.
    crate::mapped_file::sync_all_files(Some(ops.inode_attrs().dev));
    match poll_blocking(ops.syncfs()) {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(errno_ret(EIO)),
    }
}
