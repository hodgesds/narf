#[allow(unused_imports)]
use super::*;

fn scatter_to_iovecs(iovecs: &[ImportedRwIovec], mut offset: usize, mut bytes: &[u8]) -> Result<(), u64> {
    for iovec in iovecs {
        if offset >= iovec.len {
            offset -= iovec.len;
            continue;
        }
        if bytes.is_empty() {
            break;
        }
        let n = core::cmp::min(iovec.len - offset, bytes.len());
        if n != 0 {
            // SAFETY: import_rw_iovecs validated every full destination range;
            // guarded copy catches a racing unmap.
            unsafe { copy_to_user(iovec.base + offset as u64, &bytes[..n]) }?;
            bytes = &bytes[n..];
        }
        offset = 0;
    }
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(EFAULT as u64)
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
        Err(EFAULT as u64)
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
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    if !endpoint.readable() {
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

    // A socket readv is one recvmsg into one iterator.  Dequeue exactly one
    // AF_PACKET record, scatter it once, and keep packet-specific pending
    // errors intact instead of translating them through FsError.
    if let Some(packet) = crate::socket::packet::packet_socket_of(endpoint.ops.as_ref()) {
        let mut staging = alloc::vec![0u8; count];
        match packet.packet_read(&mut staging) {
            Ok(n) => match scatter_to_iovecs(&iovecs, 0, &staging[..n]) {
                Ok(()) => ctx.set_return(SyscallReturn::ok(n as u64)),
                Err(errno) => ctx.set_return(errno_ret(errno as i64)),
            },
            Err(errno) if errno == EAGAIN => {
                if endpoint.nonblocking() {
                    ctx.set_return(errno_ret(EAGAIN));
                } else if has_interrupting_signal(task) {
                    ctx.set_return(errno_ret(EINTR));
                } else if handler_sys_read::park_blocking_read(ctx, endpoint.ops.as_ref()) {
                    return;
                } else {
                    ctx.set_return(SyscallReturn::ok(0));
                }
            }
            Err(errno) => ctx.set_return(errno_ret(errno)),
        }
        return;
    }
    if crate::pipe::is_pipe(endpoint.ops.as_ref()) {
        read_pipe_user(ctx, &endpoint, count, |mut offset, mut src, mut len| {
            for iov in &iovecs {
                if offset >= iov.len { offset -= iov.len; continue; }
                let n = len.min(iov.len - offset);
                // SAFETY: retained source fragment and imported destination;
                // no Rust reference is formed over a mutable user-page pin.
                unsafe { copy_raw_to_user(iov.base + offset as u64, src, n) }?;
                len -= n;
                if len == 0 { return Ok(()); }
                // SAFETY: n bytes were consumed from this retained fragment.
                src = unsafe { src.add(n) };
                offset = 0;
            }
            Err(EFAULT as u64)
        });
        return;
    }
    // Past `if (!tot_len) goto out;`, a directory reaches
    // do_loop_readv_writev -> generic_read_dir: -EISDIR.
    if endpoint.ops.as_dir().is_some() {
        ctx.set_return(errno_ret(EISDIR));
        return;
    }

    if let Some(ret) = tty_background_access(task, endpoint.ops.as_ref(), false) {
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
            Err(errno) => ctx.set_return(errno_ret(errno as i64)),
        }
        return;
    }
    if endpoint.ops.tty_id() == Some(narf_filesystem::TTY_ID_CONSOLE) {
        note_console_reader(task);
    }

    // Anonymous pipes and named FIFOs hold their queue prefix until every
    // vector destination copy succeeds, closing the validate→unmap race.
    let mut copied = 0usize;
    if let Some(outcome) =
        handler_sys_read::transactional_stream_read(endpoint.ops.as_ref(), count, |bytes| {
            scatter_to_iovecs(&iovecs, copied, bytes)?;
            copied += bytes.len();
            Ok(())
        })
    {
        match outcome {
            Ok(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            Err(handler_sys_read::TransactionalReadError::User(errno)) => {
                ctx.set_return(errno_ret(errno as i64));
            }
            Err(handler_sys_read::TransactionalReadError::BadFd) => {
                ctx.set_return(errno_ret(EBADF));
            }
            Err(handler_sys_read::TransactionalReadError::WouldBlock)
                if endpoint.nonblocking() || endpoint.ops.nonblock_read_eagain() =>
            {
                ctx.set_return(errno_ret(EAGAIN));
            }
            Err(handler_sys_read::TransactionalReadError::WouldBlock) => {
                if has_interrupting_signal(task) {
                    ctx.set_return(errno_ret(EINTR));
                } else if handler_sys_read::park_blocking_read(ctx, endpoint.ops.as_ref()) {
                    return;
                } else {
                    ctx.set_return(SyscallReturn::ok(0));
                }
            }
        }
        return;
    }

    // Linux `fdget_pos`: only FMODE_ATOMIC_POS files lock their position.
    let _position_guard = if !endpoint.description.locks_position(endpoint.ops.as_ref()) {
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

    const CHUNK: usize = 64 * 1024;
    let mut total = 0usize;
    let mut offset = endpoint.description.offset();
    // vfs_readv: rw_verify_area(READ, file, &f_pos, tot_len) -> -EINVAL when
    // the position plus the vector length passes LLONG_MAX.
    if !endpoint.ops.is_stream() {
        if let Err(errno) = rw_verify_area_pos(offset, count) {
            ctx.set_return(errno_ret(errno));
            return;
        }
    }
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
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                if endpoint.nonblocking() || endpoint.ops.nonblock_read_eagain() {
                    ctx.set_return(errno_ret(EAGAIN));
                } else if has_interrupting_signal(task) {
                    ctx.set_return(errno_ret(EINTR));
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
                    ctx.set_return(errno_ret(copy_fs_errno(error)));
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
                ctx.set_return(errno_ret(errno as i64));
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
