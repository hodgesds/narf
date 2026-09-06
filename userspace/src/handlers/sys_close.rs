#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_close(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    // Remove the slot in one fd-table transaction, but keep its backing Arc
    // alive for flush and object-specific cleanup below. Linux makes the fd
    // unavailable before the potentially blocking flush hook too.
    let Some(entry) = fd::with_table(task, |table| table.take(fd)).flatten() else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    let ops = &entry.ops;
    // Linux invokes the filesystem flush hook for each closing file
    // description. The descriptor remains removed even if flushing fails.
    let _ = poll_blocking(ops.flush());
    if let Some(sock) = ops
        .as_any()
        .and_then(|ops| ops.downcast_ref::<crate::socket::SocketFile>())
    {
        // Unnamed socketpair endpoints have no global registration, so they
        // avoid all alias scans. A duplicated listener remains bound when
        // either descriptor is closed; Arc strong counts also include epoll
        // and ancillary-data references and therefore cannot answer this.
        if sock.has_registration() {
            let has_duplicate =
                fd::with_table(task, |table| table.contains_ops(ops)).unwrap_or(false);
            // `contains_ops` only sees THIS process's descriptors. A fork gives
            // every child its own table holding the same file description, so
            // each of them looks like the last owner. Linux ties the binding
            // to the socket's lifetime: release it only when no other table
            // owns this description either.
            if !has_duplicate && !fd::ops_held_by_other_task(task, ops) {
                sock.unregister();
            }
        }
    }
    // inotify: IN_CLOSE_WRITE for the file (before we drop its path),
    // then forget the fd → path mapping.
    {
        crate::mqueue::notify_close_fd(task, fd);
        crate::mqueue::forget_fd_path(task, fd);
    }
    ctx.set_return(SyscallReturn::ok(0));
}
