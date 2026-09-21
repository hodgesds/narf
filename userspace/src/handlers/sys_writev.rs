#[allow(unused_imports)]
use super::*;

/// Linux writev(2), flattened into bounded kernel chunks. Import validates all
/// iovecs before the first write; a small whole vector reaches a pipe as one
/// FileOps call, preserving PIPE_BUF atomicity across iovec boundaries.
pub(crate) fn sys_writev(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd_num = args.arg0 as u32;
    let task = current_task_id();

    let Some(endpoint) = copy_fd_endpoint(task, fd_num) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    if !endpoint.writable() {
        ctx.set_return(errno_ret(EBADF));
        return;
    }
    let iovecs = match import_rw_iovecs(args.arg1, args.arg2 as usize) {
        Ok(iovecs) => iovecs,
        Err(errno) => {
            ctx.set_return(errno_ret(errno as i64));
            return;
        }
    };
    let count: usize = iovecs.iter().map(|iov| iov.len).sum();
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
                ctx.set_return(errno_ret(EIO));
                return;
            }
        }
    };
    let _append_guard = if endpoint.append() {
        match poll_blocking(endpoint.description.append_lock().lock()) {
            Some(guard) => Some(guard),
            None => {
                ctx.set_return(errno_ret(EIO));
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
    // RLIMIT_FSIZE, as `generic_write_checks` applies it to the whole iov
    // run: the limit is a property of the file position, not of any one
    // iovec, so it shortens the total and the loop below stops early.
    let count = match fsize_check_write(task, offset, count, || endpoint.ops.stat().mode.file_type == narf_filesystem::FileType::File) {
        Ok(c) => c,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let mut iov_index = 0usize;
    let mut iov_offset = 0usize;
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        let mut payload = alloc::vec::Vec::with_capacity(want);
        let mut copy_failed = None;
        while payload.len() < want {
            while iov_index < iovecs.len() && iov_offset == iovecs[iov_index].len {
                iov_index += 1;
                iov_offset = 0;
            }
            let Some(iovec) = iovecs.get(iov_index) else {
                break;
            };
            let n = core::cmp::min(iovec.len - iov_offset, want - payload.len());
            // SAFETY: import validated the source; guarded copy catches a
            // protection change before this chunk is submitted.
            match unsafe { copy_from_user_vec(iovec.base + iov_offset as u64, n) } {
                Ok(bytes) => payload.extend_from_slice(&bytes),
                Err(errno) => {
                    copy_failed = Some(errno);
                    break;
                }
            }
            iov_offset += n;
        }
        if let Some(errno) = copy_failed {
            if total == 0 {
                ctx.set_return(errno_ret(errno as i64));
                return;
            }
            break;
        }
        if payload.is_empty() {
            break;
        }
        if endpoint.append() {
            offset = endpoint.ops.stat().size;
        }
        let outcome = poll_blocking(endpoint.ops.write(offset, &payload))
            .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
        match outcome {
            Ok(0) if endpoint.ops.write_should_block() && total == 0 => {
                if endpoint.nonblocking() {
                    ctx.set_return(errno_ret(EAGAIN));
                } else if has_interrupting_signal(task) {
                    ctx.set_return(errno_ret(EINTR));
                } else if park_reexecute_on_fd(
                    ctx,
                    endpoint.ops.as_ref(),
                    narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
                ) {
                    return;
                } else {
                    ctx.set_return(SyscallReturn::ok(0));
                }
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
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                if endpoint.nonblocking() {
                    ctx.set_return(errno_ret(EAGAIN));
                } else if has_interrupting_signal(task) {
                    ctx.set_return(errno_ret(EINTR));
                } else if park_reexecute_on_fd(
                    ctx,
                    endpoint.ops.as_ref(),
                    narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
                ) {
                    return;
                } else {
                    ctx.set_return(SyscallReturn::ok(0));
                }
                return;
            }
            Err(narf_filesystem::FsError::WouldBlock) => break,
            Err(narf_filesystem::FsError::BrokenPipe) => {
                raise_signal_pending(task, 13);
                if total == 0 {
                    ctx.set_return(errno_ret(EPIPE));
                    return;
                }
                break;
            }
            Err(error) => {
                if total == 0 {
                    ctx.set_return(errno_ret(copy_fs_errno(error)));
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
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
