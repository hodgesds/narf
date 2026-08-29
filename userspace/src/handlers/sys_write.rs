#[allow(unused_imports)]
use super::*;

/// `write(fd, buf, count)` with Linux `vfs_write` validation/error ordering.
pub(crate) fn sys_write(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd_num = args.arg0 as u32;
    let user_ptr = args.arg1;
    let requested = args.arg2 as usize;
    let task = current_task_id();

    // ksys_write resolves fd first; vfs_write then checks FMODE_WRITE before
    // access_ok, including for count==0.
    let Some(endpoint) = copy_fd_endpoint(task, fd_num) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
        return;
    };
    if !endpoint.writable() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    }
    if let Err(errno) = validate_rw_user_range(user_ptr, requested) {
        ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
        return;
    }
    let count = core::cmp::min(requested, LINUX_MAX_RW_COUNT);
    if count == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    let _position_guard = if endpoint.ops.is_stream() {
        None
    } else {
        match poll_blocking(endpoint.description.position_lock.lock()) {
            Some(guard) => Some(guard),
            None => {
                ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                return;
            }
        }
    };
    let _append_guard = if endpoint.append() {
        match poll_blocking(endpoint.description.append_lock().lock()) {
            Some(guard) => Some(guard),
            None => {
                ctx.set_return(SyscallReturn::ok((-5i64) as u64));
                return;
            }
        }
    } else {
        None
    };

    const CHUNK: usize = 64 * 1024;
    let mut total = 0usize;
    let mut offset = if endpoint.append() {
        endpoint.ops.stat().size
    } else {
        endpoint.description.offset()
    };
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        // SAFETY: the complete original range passed validate_rw_user_range;
        // each bounded guarded copy still catches a racing unmap.
        let payload = match unsafe { copy_from_user_vec(user_ptr + total as u64, want) } {
            Ok(payload) => payload,
            Err(errno) if total == 0 => {
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                return;
            }
            Err(_) => break,
        };
        if endpoint.append() {
            offset = endpoint.ops.stat().size;
        }
        let outcome = poll_blocking(endpoint.ops.write(offset, &payload))
            .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
        match outcome {
            Ok(0) if endpoint.ops.write_should_block() && total == 0 => {
                if endpoint.nonblocking() {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                if has_interrupting_signal(task) {
                    ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // EINTR
                    return;
                }
                if park_reexecute_on_fd(
                    ctx,
                    endpoint.ops.as_ref(),
                    narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
                ) {
                    return;
                }
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            Ok(0) => break,
            Ok(written) if written <= payload.len() => {
                total += written;
                offset = offset.saturating_add(written as u64);
                if written < payload.len() {
                    break;
                }
            }
            Ok(_) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                if endpoint.nonblocking() {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                if has_interrupting_signal(task) {
                    ctx.set_return(SyscallReturn::ok((-4i64) as u64));
                    return;
                }
                if park_reexecute_on_fd(
                    ctx,
                    endpoint.ops.as_ref(),
                    narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
                ) {
                    return;
                }
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            Err(narf_filesystem::FsError::BrokenPipe) => {
                raise_signal_pending(task, 13); // SIGPIPE even after a prefix
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-32i64) as u64));
                    return;
                }
                break;
            }
            Err(error) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64));
                    return;
                }
                break;
            }
        }
    }

    if !endpoint.ops.is_stream() {
        endpoint.description.set_offset(offset);
    }
    if total != 0 {
        crate::mqueue::notify_modify_fd(task, fd_num);
        // Re-enqueue a FIFO reader parked on the empty buffer (see the helper).
        wake_fifo_io_waiters(endpoint.ops.as_ref());
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
