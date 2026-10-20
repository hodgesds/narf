#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_close(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    // Remove the slot in one fd-table transaction, but keep its backing Arc
    // alive for flush and object-specific cleanup below. Linux makes the fd
    // unavailable before the potentially blocking flush hook too.
    let Some(entry) = fd::with_table(task, |table| table.take(fd)).flatten() else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    let ops = &entry.ops;
    // Linux invokes the filesystem flush hook for each closing file
    // description. The descriptor remains removed even if flushing fails.
    if ops.has_flush() {
        let _ = poll_blocking(ops.flush());
    }
    fd::release_closed(task, [ops.clone()]);
    // inotify: IN_CLOSE_WRITE for the file (before we drop its path),
    // then forget the fd → path mapping.
    {
        crate::mqueue::notify_close_fd(task, fd, ops.mq_queue_id());
        crate::mqueue::forget_fd_path(task, fd);
    }
    ctx.set_return(SyscallReturn::ok(0));
}
