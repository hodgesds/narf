#[allow(unused_imports)]
use super::*;

/// `tee(fd_in, fd_out, len, flags)` — duplicate up to `len` bytes from one
/// pipe into another WITHOUT consuming the input.
///
/// `fs/splice.c::do_tee` ordering:
///
/// ```text
///   if (unlikely(flags & ~SPLICE_F_ALL)) return -EINVAL;
///   if (unlikely(!len)) return 0;
///   in = fdget(fdin);  if (!in) return -EBADF;
///   ... out = fdget(fdout); if (!out) return -EBADF;
///   /* do_tee: */
///   if (!(in->f_mode & FMODE_READ) || !(out->f_mode & FMODE_WRITE)) -EBADF;
///   if (!ipipe || !opipe || ipipe == opipe) return -EINVAL;
///   /* ipipe_prep: empty source waits, -EAGAIN under SPLICE_F_NONBLOCK,
///      -ERESTARTSYS on a signal, and 0 only once !pipe->writers */
/// ```
///
/// Two divergences are fixed here. A closed descriptor answered EINVAL where
/// Linux answers EBADF, and — the worse one — an open-but-empty source pipe
/// returned 0, which every caller reads as end-of-stream. Linux only returns
/// 0 once the write end is gone; a transient empty pipe blocks or EAGAINs.
pub(crate) fn sys_tee(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let fd_in = a.arg0 as u32;
    let fd_out = a.arg1 as u32;
    let len = a.arg2 as usize;
    let flags = a.arg3;
    const SPLICE_F_NONBLOCK: u64 = 0x2;
    const SPLICE_F_ALL: u64 = 0xf; // MOVE | NONBLOCK | MORE | GIFT
    let task = current_task_id();

    if flags & !SPLICE_F_ALL != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let Some(input) = copy_fd_endpoint(task, fd_in) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    let Some(output) = copy_fd_endpoint(task, fd_out) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    if !input.readable() || !output.writable() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    }
    // tee(2) is defined only between two distinct pipes.
    if !input.is_pipe() || !output.is_pipe() {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let same_pipe = input
        .ops
        .readiness()
        .zip(output.ops.readiness())
        .is_some_and(|(left, right)| core::ptr::eq(left, right));
    if same_pipe {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    // Peek without consuming: tee leaves the source queue intact.
    let data = input.ops.pipe_peek(len).unwrap_or_default();
    if data.is_empty() {
        // An empty pipe whose write end is still open is NOT end-of-stream.
        if input.ops.poll_readiness() & narf_filesystem::POLL_HUP != 0 {
            ctx.set_return(SyscallReturn::ok(0)); // real EOF: no writers left
            return;
        }
        let nonblock = flags & SPLICE_F_NONBLOCK != 0
            || input.nonblocking()
            || output.nonblocking();
        if nonblock {
            ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
            return;
        }
        if has_interrupting_signal(task) {
            ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // -EINTR
            return;
        }
        // Nothing has been consumed, so re-executing the whole tee is safe.
        if park_reexecute_on_fd(
            ctx,
            input.ops.as_ref(),
            narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
        ) {
            return;
        }
        // Kernel-test context cannot park; report the non-blocking answer.
        ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        return;
    }

    match poll_blocking(output.ops.write(0, &data)) {
        Some(Ok(n)) => ctx.set_return(SyscallReturn::ok(n as u64)),
        Some(Err(narf_filesystem::FsError::WouldBlock)) => {
            if flags & SPLICE_F_NONBLOCK != 0
                || input.nonblocking()
                || output.nonblocking()
            {
                ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                return;
            }
            if park_reexecute_on_fd(
                ctx,
                output.ops.as_ref(),
                narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
            ) {
                return;
            }
            ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        }
        Some(Err(narf_filesystem::FsError::BrokenPipe)) => {
            raise_signal_pending(task, 13); // SIGPIPE
            ctx.set_return(SyscallReturn::ok((-32i64) as u64));
        }
        Some(Err(error)) => ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64)),
        None => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
    }
}
