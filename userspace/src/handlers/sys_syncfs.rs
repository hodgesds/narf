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
    let mapped = crate::mapped_file::sync_all_files(Some(ops.inode_attrs().dev));
    // Both run; the filesystem's own failure is reported first, then a
    // mapped page that could not be written (Linux ≥ 5.8 `syncfs` returns
    // `sb->s_wb_err`, which writeback of those pages sets).
    // A fatal signal ends the wait; the commit finishes without this task
    // (`killable_wait::syncfs`).
    let committed = match crate::killable_wait::syncfs(&ops) {
        Ok(outcome) => outcome,
        Err(crate::killable_wait::Killed) => {
            ctx.set_return(errno_ret(EINTR));
            return;
        }
    };
    match (committed, mapped) {
        (Some(Ok(())), Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        (Some(Ok(())), Err(error)) => ctx.set_return(errno_ret(copy_fs_errno(error))),
        _ => ctx.set_return(errno_ret(EIO)),
    }
}
