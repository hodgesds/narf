#[allow(unused_imports)]
use super::*;

const MAX_RW_COUNT: usize = 0x7fff_f000;

fn finish_sendfile(ctx: &mut dyn TrapContext, offset_ptr: u64, offset: u64, result: i64) {
    if offset_ptr != 0 {
        // Linux's syscall wrapper performs put_user() after do_sendfile even
        // when the transfer returned an error, so a write-back fault wins.
        // SAFETY: copy_to_user validates and brackets the user access.
        if unsafe { copy_to_user(offset_ptr, &offset.to_ne_bytes()) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
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
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
                return;
            }
        };
        u64::from_ne_bytes(bytes.try_into().unwrap())
    } else {
        0
    };

    // Input fd and FMODE_READ precede every output-side check.
    let Some(input) = copy_fd_endpoint(task, in_fd) else {
        finish_sendfile(ctx, offset_ptr, initial_offset, -9); // EBADF
        return;
    };
    if !input.readable() {
        finish_sendfile(ctx, offset_ptr, initial_offset, -9); // EBADF
        return;
    }
    if offset_ptr != 0 && input.ops.is_stream() {
        // Explicit offsets require FMODE_PREAD; pipes/sockets fail ESPIPE.
        finish_sendfile(ctx, offset_ptr, initial_offset, -29);
        return;
    }
    if offset_ptr == 0 && input.ops.is_stream() {
        // NARF streams do not provide Linux's splice_read/mmap source op.
        // Fail closed so an empty live pipe can never masquerade as EOF.
        finish_sendfile(ctx, offset_ptr, initial_offset, -22);
        return;
    }

    let transfer_offset = if offset_ptr != 0 {
        if (initial_offset as i64) < 0
            || requested > isize::MAX as usize
            || initial_offset
                .checked_add(requested as u64)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            finish_sendfile(ctx, offset_ptr, initial_offset, -22); // EINVAL
            return;
        }
        Some(initial_offset)
    } else {
        None
    };

    // Linux checks output only after the input fd/mode/range is valid.
    let Some(output) = copy_fd_endpoint(task, out_fd) else {
        finish_sendfile(ctx, offset_ptr, initial_offset, -9); // EBADF
        return;
    };
    if !output.writable() {
        finish_sendfile(ctx, offset_ptr, initial_offset, -9); // EBADF
        return;
    }
    if output.append() {
        finish_sendfile(ctx, offset_ptr, initial_offset, -22); // EINVAL
        return;
    }

    let count = core::cmp::min(requested, MAX_RW_COUNT);
    if count != 0
        && output.is_pipe()
        && output.ops.poll_readiness() & narf_filesystem::POLL_OUT == 0
        && output.ops.write_should_block()
    {
        if output.nonblocking() {
            finish_sendfile(ctx, offset_ptr, initial_offset, -(EAGAIN_CODE as i64));
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
    let (result, advanced) =
        match copy_fd_to_fd(&input, &output, transfer_offset, None, count) {
            Ok(total) => (total as i64, total as u64),
            Err(CopyFdError::Fs(narf_filesystem::FsError::WouldBlock)) => {
                if output.nonblocking() {
                    (-(EAGAIN_CODE as i64), 0)
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
                (-32, 0)
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
