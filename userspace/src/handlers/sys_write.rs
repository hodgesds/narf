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

    // `inode_permission`'s "Nobody gets write access to an immutable
    // file", and the append-only half: the data may grow but never be
    // rewritten, so only an O_APPEND write is allowed through.
    if let Err(errno) = immutable_check(endpoint.ops.inode_flags(), true, endpoint.append()) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // `vfs_write` -> `file_remove_privs`: a write strips the set-user-ID
    // bit (and set-group-ID, when it is a privilege rather than the
    // mandatory-locking marker). Without this, anyone who can write a
    // set-user-ID-root binary keeps it set-user-ID-root.
    // The starting position is needed BEFORE `file_remove_privs`: Linux
    // reaches `generic_write_checks` (and its RLIMIT_FSIZE test) from inside
    // `generic_file_write_iter`, ahead of the `file_modified` that strips
    // set-user-ID. A write refused with -EFBIG must therefore leave the mode
    // bits alone — stripping them would let an unprivileged caller disarm a
    // set-user-ID binary with a write it is not even allowed to perform.
    //
    // For an O_APPEND write the position is `i_size`, read under the append
    // lock taken above, so the limit is tested against the offset the write
    // will actually use.
    let mut offset = if endpoint.append() {
        endpoint.ops.stat().size
    } else {
        endpoint.description.offset()
    };
    let count = match fsize_check_write(task, offset, count, || endpoint.ops.stat().mode.file_type == narf_filesystem::FileType::File) {
        Ok(c) => c,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };

    file_remove_privs(endpoint.ops.as_ref(), task);

    const CHUNK: usize = 64 * 1024;
    let mut total = 0usize;
    let pipe_write = endpoint
        .ops
        .as_any()
        .and_then(|any| any.downcast_ref::<crate::pipe::PipeWrite>());
    let fifo_write = endpoint
        .ops
        .as_any()
        .and_then(|any| any.downcast_ref::<narf_filesystem::fifo::FifoHandle>());
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        let outcome = if let Some(pipe) = pipe_write {
            match pipe.write_from_user(user_ptr + total as u64, want) {
                Ok(outcome) => outcome,
                Err(errno) if total == 0 => {
                    ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                    return;
                }
                Err(_) => break,
            }
        } else if let Some(fifo) = fifo_write {
            let copied = fifo.write_from_user(want, |dst| {
                // SAFETY: the complete original range passed
                // validate_rw_user_range; the guarded copy catches a racing
                // unmap after FIFO peer/fullness checks, as Linux does.
                unsafe { copy_from_user(dst, user_ptr + total as u64) }
            });
            match copied {
                Ok(written) => Ok(written),
                Err(narf_filesystem::fifo::FifoWriteError::WouldBlock) => {
                    Err(narf_filesystem::FsError::WouldBlock)
                }
                Err(narf_filesystem::fifo::FifoWriteError::BadFd) => {
                    Err(narf_filesystem::FsError::BadFd)
                }
                Err(narf_filesystem::fifo::FifoWriteError::BrokenPipe) => {
                    Err(narf_filesystem::FsError::BrokenPipe)
                }
                Err(narf_filesystem::fifo::FifoWriteError::User(errno)) if total == 0 => {
                    ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                    return;
                }
                Err(narf_filesystem::fifo::FifoWriteError::User(_)) => break,
            }
        } else {
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
            poll_blocking(endpoint.ops.write(offset, &payload))
                .unwrap_or(Err(narf_filesystem::FsError::WouldBlock))
        };
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
            Ok(written) if written <= want => {
                total += written;
                offset = offset.saturating_add(written as u64);
                if written < want {
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
