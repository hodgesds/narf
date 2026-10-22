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
    // Commit this file's generic-fallback MAP_SHARED pages first: the
    // filesystem's own syncfs walk cannot see the userspace fallback
    // cache. (Filesystem-wide reach for other files' fallback pages is
    // sync(2)'s job; the cache records no per-filesystem grouping.)
    let _ = crate::mapped_file::flush_shared_pages_for_ops(&ops);
    match poll_blocking(ops.syncfs()) {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(errno_ret(EIO)),
    }
}
