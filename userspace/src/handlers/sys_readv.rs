#[allow(unused_imports)]
use super::*;

fn scatter_to_iovecs(iovecs: &[ImportedRwIovec], mut bytes: &[u8]) -> Result<(), u64> {
    for iovec in iovecs {
        if bytes.is_empty() {
            break;
        }
        let n = core::cmp::min(iovec.len, bytes.len());
        if n != 0 {
            // SAFETY: import_rw_iovecs validated every full destination range;
            // guarded copy catches a racing unmap.
            unsafe { copy_to_user(iovec.base, &bytes[..n]) }?;
            bytes = &bytes[n..];
        }
    }
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(EFAULT)
    }
}

/// Fanotify has a stricter destination rule than an ordinary read: x86 keeps
/// supervisor low-memory aliases mapped while a user CR3 is active, so event
/// metadata must additionally prove that every destination page belongs to
/// the active user address space before object fds can be published. Keep that
/// policy confined to the fanotify branch; applying it to generic readv would
/// reject valid guarded copies (including AP kernel-test scratch buffers).
fn scatter_fanotify_to_iovecs(iovecs: &[ImportedRwIovec], mut bytes: &[u8]) -> Result<(), u64> {
    for iovec in iovecs {
        if bytes.is_empty() {
            break;
        }
        let n = core::cmp::min(iovec.len, bytes.len());
        if n != 0 {
            validate_fanotify_copy_range(iovec.base, n)?;
            // SAFETY: fanotify validation proved active-AS ownership and the
            // guarded copy catches a racing unmap before fd publication.
            unsafe { copy_to_user(iovec.base, &bytes[..n]) }?;
            bytes = &bytes[n..];
        }
    }
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(EFAULT)
    }
}

/// Linux readv(2): fd/mode validation precedes iovec import; the complete
/// vector is range-checked before I/O; effective length is MAX_RW_COUNT-capped;
/// and errors after a transferred prefix return that prefix.
pub(crate) fn sys_readv(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd_num = args.arg0 as u32;
    let task = current_task_id();

    let Some(endpoint) = copy_fd_endpoint(task, fd_num) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    };
    if !endpoint.readable() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    }
    let iovecs = match import_rw_iovecs(args.arg1, args.arg2 as usize) {
        Ok(iovecs) => iovecs,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
            return;
        }
    };
    let count: usize = iovecs.iter().map(|iov| iov.len).sum();
    if count == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    if let Some(ret) = tty_background_access(task, fd_num, false) {
        ctx.set_return(SyscallReturn::ok(ret as u64));
        return;
    }

    let fanotify_group = crate::mqueue::fanotify_active()
        .then(|| crate::mqueue::fanotify_instance_of(task, fd_num))
        .flatten();
    if let Some(group) = fanotify_group {
        let max = core::cmp::min(count, 64 * 1024);
        match fanotify_read_to_user(task, group, max, |bytes| {
            scatter_fanotify_to_iovecs(&iovecs, bytes)
        }) {
            Ok(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            Err(errno) => ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64)),
        }
        return;
    }
    note_console_reader(task);

    // Anonymous pipes and named FIFOs hold their queue prefix until every
    // vector destination copy succeeds, closing the validate→unmap race.
    if let Some(outcome) =
        handler_sys_read::transactional_stream_read(endpoint.ops.as_ref(), count, |bytes| {
            scatter_to_iovecs(&iovecs, bytes)
        })
    {
        match outcome {
            Ok(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            Err(handler_sys_read::TransactionalReadError::User(errno)) => {
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
            }
            Err(handler_sys_read::TransactionalReadError::BadFd) => {
                ctx.set_return(SyscallReturn::ok((-9i64) as u64));
            }
            Err(handler_sys_read::TransactionalReadError::WouldBlock)
                if endpoint.nonblocking() || endpoint.ops.nonblock_read_eagain() =>
            {
                ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
            }
            Err(handler_sys_read::TransactionalReadError::WouldBlock) => {
                if has_interrupting_signal(task) {
                    ctx.set_return(SyscallReturn::ok((-4i64) as u64));
                } else if handler_sys_read::park_blocking_read(ctx, endpoint.ops.as_ref()) {
                    return;
                } else {
                    ctx.set_return(SyscallReturn::ok(0));
                }
            }
        }
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

    const CHUNK: usize = 64 * 1024;
    let mut total = 0usize;
    let mut offset = endpoint.description.offset();
    let mut iov_index = 0usize;
    let mut iov_offset = 0usize;
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        let mut staging = alloc::vec![0u8; want];
        let outcome = poll_blocking(endpoint.ops.read(offset, &mut staging))
            .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
        let read = match outcome {
            Ok(0) => break,
            Ok(n) if n <= want => n,
            Ok(_) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                if endpoint.nonblocking() || endpoint.ops.nonblock_read_eagain() {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                } else if has_interrupting_signal(task) {
                    ctx.set_return(SyscallReturn::ok((-4i64) as u64));
                } else if handler_sys_read::park_blocking_read(ctx, endpoint.ops.as_ref()) {
                    return;
                } else {
                    ctx.set_return(SyscallReturn::ok(0));
                }
                return;
            }
            Err(narf_filesystem::FsError::WouldBlock) => break,
            Err(error) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64));
                    return;
                }
                break;
            }
        };

        let mut copied = 0usize;
        let mut copy_failed = None;
        while copied < read {
            while iov_index < iovecs.len() && iov_offset == iovecs[iov_index].len {
                iov_index += 1;
                iov_offset = 0;
            }
            let Some(iovec) = iovecs.get(iov_index) else {
                break;
            };
            let n = core::cmp::min(iovec.len - iov_offset, read - copied);
            // SAFETY: imported destination; guarded against racing unmap.
            if let Err(errno) = unsafe {
                copy_to_user(iovec.base + iov_offset as u64, &staging[copied..copied + n])
            } {
                copy_failed = Some(errno);
                break;
            }
            copied += n;
            iov_offset += n;
        }
        if let Some(errno) = copy_failed {
            // Non-pipe FileOps may already have advanced internal state; report
            // only bytes actually copied, matching Linux iterator progress.
            total += copied;
            offset = offset.saturating_add(copied as u64);
            if total == 0 {
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                return;
            }
            break;
        }
        total += read;
        offset = offset.saturating_add(read as u64);
        if read < want {
            break;
        }
    }

    if !endpoint.ops.is_stream() {
        endpoint.description.set_offset(offset);
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
