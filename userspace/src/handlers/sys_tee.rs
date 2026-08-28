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

    // Anonymous pipe on both sides: duplicate buffers directly, so each
    // buffer's PIPE_BUF_FLAG_PACKET reaches the destination.
    // `fs/splice.c::link_pipe` copies `*obuf = *ibuf` and clears only GIFT and
    // CAN_MERGE, so a teed packet is still a packet on the far side. Going
    // through `pipe_peek` + the destination's ordinary `write` instead handed
    // the payload to the destination's OWN framing: teeing a packet pipe ran
    // every record together, and teeing into a packet pipe invented record
    // boundaries the source never had.
    let paired = input
        .ops
        .as_any()
        .and_then(|any| any.downcast_ref::<crate::pipe::PipeRead>())
        .zip(
            output
                .ops
                .as_any()
                .and_then(|any| any.downcast_ref::<crate::pipe::PipeWrite>()),
        );
    if let Some((pipe_in, pipe_out)) = paired {
        match pipe_in.tee_to(pipe_out, len) {
            // 0 reaches here only from `ipipe_prep`'s end-of-stream arm — an
            // empty source whose last writer is gone. Every other empty-source
            // case is WouldBlock below, so a caller never reads a transient
            // empty pipe as EOF.
            Ok(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            Err(narf_filesystem::FsError::WouldBlock) => {
                tee_wait(ctx, task, &input, &output, flags);
            }
            Err(narf_filesystem::FsError::BrokenPipe) => {
                raise_signal_pending(task, 13); // SIGPIPE
                ctx.set_return(SyscallReturn::ok((-32i64) as u64));
            }
            Err(error) => ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64)),
        }
        return;
    }

    // Fallback for a FIFO that is not an anonymous pipe pair: peek without
    // consuming (tee leaves the source queue intact) and write the bytes.
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

/// `tee_to` reports WouldBlock for two distinct states — an empty source with
/// its writer still open, and a destination with no room — and Linux waits on
/// a different pipe in each case (`ipipe_prep` on the source, the output-room
/// loop on the destination). Park on whichever is actually blocking, or the
/// caller sleeps on an fd that will never signal.
fn tee_wait(
    ctx: &mut dyn TrapContext,
    task: u64,
    input: &CopyFdEndpoint,
    output: &CopyFdEndpoint,
    flags: u64,
) {
    const SPLICE_F_NONBLOCK: u64 = 0x2;
    let source_empty = input.ops.poll_readiness() & narf_filesystem::POLL_IN == 0;
    if flags & SPLICE_F_NONBLOCK != 0 || input.nonblocking() || output.nonblocking() {
        ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        return;
    }
    if source_empty && has_interrupting_signal(task) {
        // `ipipe_prep` returns -ERESTARTSYS from the source wait only.
        ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // -EINTR
        return;
    }
    // Nothing has been consumed or published, so re-executing the whole tee is
    // safe from either wait.
    let (ops, mask) = if source_empty {
        (
            input.ops.as_ref(),
            narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
        )
    } else {
        (
            output.ops.as_ref(),
            narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
        )
    };
    if park_reexecute_on_fd(ctx, ops, mask) {
        return;
    }
    // Kernel-test context cannot park; report the non-blocking answer.
    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
}
