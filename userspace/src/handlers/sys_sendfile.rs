#[allow(unused_imports)]
use super::*;

const MAX_RW_COUNT: usize = 0x7fff_f000;

fn finish_sendfile(ctx: &mut dyn TrapContext, offset_ptr: u64, offset: u64, result: i64) {
    if offset_ptr != 0 {
        // Linux's syscall wrapper performs put_user() after do_sendfile even
        // when the transfer returned an error, so a write-back fault wins.
        // SAFETY: copy_to_user validates and brackets the user access.
        if unsafe { copy_to_user(offset_ptr, &offset.to_ne_bytes()) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(result as u64));
}

/// `sendfile(out_fd, in_fd, off*, count)` — Linux validation order and
/// kernel-buffered transfer semantics (`fs/read_write.c::do_sendfile`).
pub(crate) fn sys_sendfile(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let out_fd = a.arg0 as u32;
    let in_fd = a.arg1 as u32;
    let offset_ptr = a.arg2;
    let requested = a.arg3 as usize;

    // The syscall wrapper imports the optional offset before either fd.
    let initial_offset = if offset_ptr != 0 {
        // SAFETY: copy_from_user_vec validates the complete loff_t input.
        let bytes = match unsafe { copy_from_user_vec(offset_ptr, 8) } {
            Ok(bytes) => bytes,
            Err(_) => {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
        };
        u64::from_ne_bytes(bytes.try_into().unwrap())
    } else {
        0
    };

    // Input fd and FMODE_READ precede every output-side check.
    let Some(input) = copy_fd_endpoint(task, in_fd) else {
        finish_sendfile(ctx, offset_ptr, initial_offset, -EBADF);
        return;
    };
    if !input.readable() {
        finish_sendfile(ctx, offset_ptr, initial_offset, -EBADF);
        return;
    }
    if offset_ptr != 0 && input.ops.is_stream() {
        // Explicit offsets require FMODE_PREAD; pipes/sockets fail ESPIPE.
        finish_sendfile(ctx, offset_ptr, initial_offset, -ESPIPE);
        return;
    }

    // rw_verify_area(READ, in, &pos, count) runs on the explicit offset or,
    // without one, on `in->f_pos` — so `sendfile(out, in, NULL, SIZE_MAX)`
    // is -EINVAL (ssize_t count < 0), still ahead of any output-fd check.
    let verify_in = if offset_ptr != 0 {
        initial_offset
    } else {
        input.description.offset()
    };
    if let Err(errno) = rw_verify_area_pos(verify_in, requested) {
        finish_sendfile(ctx, offset_ptr, initial_offset, -errno);
        return;
    }
    let transfer_offset = (offset_ptr != 0).then_some(initial_offset);

    // Linux checks output only after the input fd/mode/range is valid.
    let Some(output) = copy_fd_endpoint(task, out_fd) else {
        finish_sendfile(ctx, offset_ptr, initial_offset, -EBADF);
        return;
    };
    if !output.writable() {
        finish_sendfile(ctx, offset_ptr, initial_offset, -EBADF);
        return;
    }
    let count = core::cmp::min(requested, MAX_RW_COUNT);
    // A non-pipe output goes through do_splice_direct: rw_verify_area(WRITE,
    // out, &out->f_pos, count), then O_APPEND -> -EINVAL.
    if !output.is_pipe() {
        if let Err(errno) = rw_verify_area_pos(output.description.offset(), count) {
            finish_sendfile(ctx, offset_ptr, initial_offset, -errno);
            return;
        }
    }
    if output.append() {
        finish_sendfile(ctx, offset_ptr, initial_offset, -EINVAL);
        return;
    }
    if count != 0
        && output.is_pipe()
        && output.ops.poll_readiness() & narf_filesystem::POLL_OUT == 0
        && output.ops.write_should_block()
    {
        if output.nonblocking() {
            finish_sendfile(ctx, offset_ptr, initial_offset, -EAGAIN);
            return;
        }
        if park_reexecute_on_fd(
            ctx,
            output.ops.as_ref(),
            narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
        ) {
            return;
        }
        finish_sendfile(ctx, offset_ptr, initial_offset, 0);
        return;
    }
    if offset_ptr == 0 && input.ops.is_stream() {
        // NARF streams do not provide Linux's splice_read/mmap source op.
        // Fail closed so an empty live pipe can never masquerade as EOF.
        // Linux 6.x also answers -EINVAL for a pipe source, but only after the
        // output fd is resolved (splice_direct_to_actor's S_ISREG test /
        // do_splice_read's missing ->splice_read): a bad out_fd is -EBADF.
        finish_sendfile(ctx, offset_ptr, initial_offset, -EINVAL);
        return;
    }
    let (result, advanced) =
        match copy_fd_to_fd(&input, &output, transfer_offset, None, count) {
            Ok(total) => (total as i64, total as u64),
            Err(CopyFdError::Fs(narf_filesystem::FsError::WouldBlock)) => {
                if output.nonblocking() {
                    (-EAGAIN, 0)
                } else {
                    // No data or position was consumed, so re-execution is safe.
                    if park_reexecute_on_fd(
                        ctx,
                        output.ops.as_ref(),
                        narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
                    ) {
                        return;
                    }
                    // Kernel-test context cannot park.
                    (0, 0)
                }
            }
            Err(CopyFdError::Fs(narf_filesystem::FsError::BrokenPipe)) => {
                raise_signal_pending(task, 13); // SIGPIPE
                (-EPIPE, 0)
            }
            Err(CopyFdError::Fs(error)) => (-copy_fs_errno(error), 0),
        };
    finish_sendfile(
        ctx,
        offset_ptr,
        initial_offset.saturating_add(advanced),
        result,
    );
}
