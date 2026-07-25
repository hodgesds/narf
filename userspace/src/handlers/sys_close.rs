#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_close(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    // Before removing the fd, peek the FileOps Arc; if it's a
    // SocketFile, run its unregister hook so a bound listener
    // releases its path slot for re-use.
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten();
    if let Some(ops) = arc_ops {
        let raw = alloc::sync::Arc::as_ptr(&ops) as *const ();
        if let Some(sock) = socket_arc_lookup(raw) {
            // Release a bound listener's path slot (no-op for a connected /
            // socketpair socket). We deliberately do NOT remove the SOCKET_ARCS
            // resolver entry here: it holds a `Weak` (see socket_arc_register)
            // that self-invalidates only when the LAST fd to the SocketFile
            // drops. A socketpair end passed to a forked child (weston's
            // helper-launch: socketpair → fork → parent closes the child's end)
            // is closed in the parent while the child still holds its inherited
            // fd to the same SocketFile — removing the entry on this close is
            // exactly what made the child's sendmsg/recvmsg unresolvable and
            // broke the libwayland handshake with EPERM.
            sock.unregister();
        }
    }
    // inotify: IN_CLOSE_WRITE for the file (before we drop its path),
    // then forget the fd → path mapping.
    #[cfg(feature = "linux-compat")]
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
