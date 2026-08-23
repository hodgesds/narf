#[allow(unused_imports)]
use super::*;

/// `splice(fd_in, off_in*, fd_out, off_out*, len, flags)` — move data
/// between two fds, at least one of which must be a pipe. NARF reuses the
/// sendfile copy core rather than moving pipe buffers by reference.
///
/// Linux shape (`fs/splice.c::__do_splice`):
///   * neither fd a pipe → -EINVAL;
///   * an offset pointer for a pipe-side fd → -ESPIPE;
///   * an empty-but-open pipe source must BLOCK (or -EAGAIN under
///     SPLICE_F_NONBLOCK), never report a transient 0 as EOF — the same
///     lost-data class as the sendfile/copy_file_range transient-EOF bugs;
///   * symmetrically, a full pipe sink blocks or EAGAINs.
pub(crate) fn sys_splice(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let fd_in = a.arg0 as u32;
    let off_in_ptr = a.arg1;
    let fd_out = a.arg2 as u32;
    let off_out_ptr = a.arg3;
    let len = a.arg4 as usize;
    let flags = a.arg5;
    /// `SPLICE_F_NONBLOCK` — do not block on pipe I/O.
    const SPLICE_F_NONBLOCK: u64 = 0x2;

    let resolved = fd::with_table(task, |t| {
        let i = t.get(fd_in)?;
        let o = t.get(fd_out)?;
        Some((i.ops.clone(), o.ops.clone()))
    });
    let (in_ops, out_ops) = match resolved {
        Some(Some(v)) => v,
        _ => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
    };
    let in_is_pipe = in_ops.stat().mode.file_type == narf_filesystem::FileType::Fifo;
    let out_is_pipe = out_ops.stat().mode.file_type == narf_filesystem::FileType::Fifo;
    if !in_is_pipe && !out_is_pipe {
        // fs/splice.c::__do_splice → -EINVAL when neither side is a pipe.
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    // fs/splice.c::__do_splice: "if (ipipe && off_in) return -ESPIPE;"
    // (and the same for opipe/off_out) — a pipe has no file position.
    if (in_is_pipe && off_in_ptr != 0) || (out_is_pipe && off_out_ptr != 0) {
        ctx.set_return(SyscallReturn::ok((-29i64) as u64));
        return;
    }
    // Full pipe sink, reader still open: EAGAIN or park+re-exec, checked
    // BEFORE any copying so nothing is consumed from fd_in (the park
    // re-executes the whole splice, which is only idempotent while the
    // source is untouched). `fs/splice.c` waits in wait_for_space().
    if len > 0
        && out_is_pipe
        && out_ops.poll_readiness() & narf_filesystem::POLL_OUT == 0
        && out_ops.write_should_block()
    {
        if flags & SPLICE_F_NONBLOCK != 0 {
            ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
            return;
        }
        if park_reexecute_on_io(ctx) {
            return;
        }
        // Kernel-test context: fall through and report the 0-byte copy.
    }
    // Pipe source: drain the ring straight into the sink (no 64 KiB zeroed
    // bounce). Non-pipe source (a pipe SINK splice, e.g. /dev/zero → pipe)
    // keeps the offset-aware copy core. off_in is guaranteed 0 for a pipe
    // source (the ESPIPE check above), so no offset write-back is needed.
    let outcome = if in_is_pipe {
        splice_pipe_source(task, fd_in, fd_out, len)
    } else {
        copy_fd_to_fd(task, fd_in, fd_out, off_in_ptr, len)
    };
    match outcome {
        Some(Err(narf_filesystem::FsError::WouldBlock)) if len > 0 && in_is_pipe => {
            // Empty pipe source, writer still open: an empty first read
            // consumes nothing, so EAGAIN or park+re-exec is safe
            // (`fs/splice.c::splice_file_to_pipe` waits via pipe_wait_*).
            // Returning the transient 0 as EOF is the lost-data shape.
            if flags & SPLICE_F_NONBLOCK != 0 {
                ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                return;
            }
            if park_reexecute_on_io(ctx) {
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Ok(total)) => ctx.set_return(SyscallReturn::ok(total as u64)),
        Some(Err(_)) | None => ctx.set_return(SyscallReturn::ok((-1i64) as u64)),
    }
}
