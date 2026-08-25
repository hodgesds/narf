#[allow(unused_imports)]
use super::*;

/// `sendfile(out_fd, in_fd, off*, count)` — copy bytes between fds in
/// the kernel. See `copy_fd_to_fd`.
pub(crate) fn sys_sendfile(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let in_fd = a.arg1 as u32;
    // Linux: the sendfile(2) input fd must support mmap. A non-seekable
    // stream (pipe/socket) is rejected with EINVAL — and that rejection is
    // load-bearing: the copy core below treats a transient empty read on a
    // still-open pipe as EOF, so a pipe source would silently truncate to 0.
    // EINVAL makes callers (busybox `cat`) fall back to a read()/write() loop
    // that parks correctly on the empty-but-open pipe.
    let in_is_stream = fd::with_table(task, |t| t.get(in_fd).map(|e| e.ops.is_stream()));
    if let Some(Some(true)) = in_is_stream {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    match copy_fd_to_fd(task, in_fd, a.arg0 as u32, a.arg2, 0, a.arg3 as usize) {
        Some(Ok(total)) => ctx.set_return(SyscallReturn::ok(total as u64)),
        Some(Err(CopyFdError::Fault)) => ctx.set_return(SyscallReturn::ok((-14i64) as u64)),
        Some(Err(_)) | None => ctx.set_return(SyscallReturn::ok((-1i64) as u64)),
    }
}
