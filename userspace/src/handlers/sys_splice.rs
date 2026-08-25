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
    let requested = a.arg4 as usize;
    let flags = a.arg5;
    const SPLICE_F_NONBLOCK: u64 = 0x2;
    const SPLICE_F_ALL: u64 = 0xf; // MOVE | NONBLOCK | MORE | GIFT

    // fs/splice.c::splice returns 0 before validating flags, fds, or offset
    // pointers.  stress-ng intentionally probes this precedence.
    if requested == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if flags & !SPLICE_F_ALL != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    // Linux fdget()s input then output, so preserve which EBADF wins.
    let Some(input) = copy_fd_endpoint(task, fd_in) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    };
    let Some(output) = copy_fd_endpoint(task, fd_out) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    };
    let in_is_pipe = input.is_pipe();
    let out_is_pipe = output.is_pipe();

    // __do_splice identifies pipe endpoints before touching userspace.
    if (in_is_pipe && off_in_ptr != 0) || (out_is_pipe && off_out_ptr != 0) {
        ctx.set_return(SyscallReturn::ok((-29i64) as u64));
        return;
    }

    // Linux imports off_out first, then off_in.  At most one can be useful
    // because a valid splice has a pipe on the other side.
    let import_offset = |ptr: u64| -> Result<Option<u64>, ()> {
        if ptr == 0 {
            return Ok(None);
        }
        // SAFETY: copy_from_user_vec validates the complete loff_t input.
        let bytes = unsafe { copy_from_user_vec(ptr, 8) }.map_err(|_| ())?;
        Ok(Some(u64::from_ne_bytes(bytes.try_into().unwrap())))
    };
    let explicit_out = match import_offset(off_out_ptr) {
        Ok(offset) => offset,
        Err(()) => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let explicit_in = match import_offset(off_in_ptr) {
        Ok(offset) => offset,
        Err(()) => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };

    // do_splice checks both f_mode bits before deciding the pipe shape.
    if !input.readable() || !output.writable() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
        return;
    }
    if !in_is_pipe && !out_is_pipe {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if explicit_in.is_some() && input.ops.is_stream()
        || explicit_out.is_some() && output.ops.is_stream()
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // lacks PREAD/PWRITE
        return;
    }
    if output.append() && !out_is_pipe {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    if requested > isize::MAX as usize
        || explicit_in.is_some_and(|offset| {
            (offset as i64) < 0
                || offset
                    .checked_add(requested as u64)
                    .is_none_or(|end| end > i64::MAX as u64)
        })
        || explicit_out.is_some_and(|offset| {
            (offset as i64) < 0
                || offset
                    .checked_add(requested as u64)
                    .is_none_or(|end| end > i64::MAX as u64)
        })
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }

    // Two descriptors for the two ends of one pipe name the same
    // pipe_inode_info on Linux and must fail EINVAL rather than lock itself.
    if in_is_pipe && out_is_pipe {
        let same_pipe = input
            .ops
            .readiness()
            .zip(output.ops.readiness())
            .is_some_and(|(left, right)| core::ptr::eq(left, right));
        if same_pipe {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        }
    }

    // A non-pipe destructive stream source has no peek/commit transaction in
    // NARF.  Fail closed instead of consuming bytes a short sink cannot take.
    let input_has_transactional_splice = input
        .ops
        .as_any()
        .and_then(|any| any.downcast_ref::<crate::pipe::PipeRead>())
        .is_some();
    if input.ops.is_stream() && !input_has_transactional_splice {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }

    let nonblock = flags & SPLICE_F_NONBLOCK != 0
        || (in_is_pipe && input.nonblocking())
        || (out_is_pipe && output.nonblocking());
    // Full pipe sink, reader still open: EAGAIN or park+re-exec, checked
    // BEFORE any copying so nothing is consumed from fd_in (the park
    // re-executes the whole splice, which is only idempotent while the
    // source is untouched). `fs/splice.c` waits in wait_for_space().
    if !in_is_pipe
        && out_is_pipe
        && output.ops.poll_readiness() & narf_filesystem::POLL_OUT == 0
        && output.ops.write_should_block()
    {
        if nonblock {
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
        // Kernel-test context: fall through and report the 0-byte copy.
    }
    // Use the established copy core for both directions. A destructive
    // pipe-take fast path used to publish source capacity before the sink had
    // accepted the bytes; a concurrent writer could refill that capacity and
    // the rollback then overfilled the pipe. A future zero-copy path needs an
    // explicit reservation/commit protocol before it can replace this path.
    let outcome = copy_fd_to_fd(&input, &output, explicit_in, explicit_out, requested);
    match outcome {
        Err(CopyFdError::Fs(narf_filesystem::FsError::WouldBlock)) => {
            // Empty source or full sink with no progress consumes nothing, so
            // EAGAIN or park+re-exec is safe. A partial transfer is returned as
            // its byte count by the copy core and is never re-executed.
            if nonblock {
                ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                return;
            }
            let (wait_ops, interest) = if in_is_pipe
                && input.ops.poll_readiness()
                    & (narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP)
                    == 0
            {
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
            if park_reexecute_on_fd(ctx, wait_ops, interest) {
                return;
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err(CopyFdError::Fs(narf_filesystem::FsError::BrokenPipe)) => {
            raise_signal_pending(task, 13); // SIGPIPE
            ctx.set_return(SyscallReturn::ok((-32i64) as u64));
        }
        Err(CopyFdError::Fs(error)) => {
            ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64));
        }
        Ok(total) => {
            // __do_splice writes explicit offsets back only after a
            // nonnegative result, in off_out then off_in order.
            if let Some(start) = explicit_out {
                // SAFETY: guarded write-back catches a racing unmap.
                if unsafe {
                    copy_to_user(
                        off_out_ptr,
                        &start.saturating_add(total as u64).to_ne_bytes(),
                    )
                }
                .is_err()
                {
                    ctx.set_return(SyscallReturn::ok((-14i64) as u64));
                    return;
                }
            }
            if let Some(start) = explicit_in {
                // SAFETY: same complete loff_t write-back contract.
                if unsafe {
                    copy_to_user(
                        off_in_ptr,
                        &start.saturating_add(total as u64).to_ne_bytes(),
                    )
                }
                .is_err()
                {
                    ctx.set_return(SyscallReturn::ok((-14i64) as u64));
                    return;
                }
            }
            ctx.set_return(SyscallReturn::ok(total as u64));
        }
    }
}
