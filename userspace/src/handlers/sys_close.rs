#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_close(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    // A duplicated listener remains bound when either descriptor is closed.
    // Check the fd table directly: Arc strong counts also include epoll and
    // ancillary-data references, so they do not represent descriptor owners.
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten();
    if let Some(ops) = arc_ops.as_ref() {
        // Linux invokes the filesystem flush hook for each closing file
        // description. The descriptor is removed even if flushing fails.
        let _ = poll_blocking(ops.flush());
        let has_duplicate = fd::with_table(task, |t| t.has_other_ops(fd, ops)).unwrap_or(false);
        if !has_duplicate {
            let raw = alloc::sync::Arc::as_ptr(ops) as *const ();
            if let Some(sock) = socket_arc_lookup(raw) {
                // `has_other_ops` only sees THIS process's descriptors. A
                // fork gives every child its own table holding the same file
                // description, so each of them looks like the last owner.
                // A child dropping an inherited listener — which is what
                // FD_CLOEXEC does on every exec in a desktop session — would
                // then unbind the path out from under a parent that is still
                // listening, and subsequent connects get ECONNREFUSED.
                //
                // Linux ties the binding to the socket's lifetime, not to one
                // descriptor. Only release the name once no other process
                // holds this description either.
                if !sock.has_registration() || !fd::ops_held_by_other_task(task, ops) {
                    sock.unregister();
                }
            }
        }
    }
    // inotify: IN_CLOSE_WRITE for the file (before we drop its path),
    // then forget the fd → path mapping.
    {
        crate::mqueue::notify_close_fd(task, fd);
        crate::mqueue::forget_fd_path(task, fd);
    }
    let ok = fd::with_table(task, |t| t.close(fd)).unwrap_or(false);
    if ok {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        // POSIX/Linux: close(2) on a fd that isn't open returns -EBADF.
        // (Was the generic InvalidOp, which musl can't map to an errno.)
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
    }
}
