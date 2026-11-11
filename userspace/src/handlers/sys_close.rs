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
    // The file's name, and the inotify close event that carries it, go with
    // the open file description when its last descriptor closes.
    crate::mqueue::notify_close_fd(task, fd, ops.mq_queue_id());
    ctx.set_return(SyscallReturn::ok(0));
}
