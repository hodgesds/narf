#[allow(unused_imports)]
use super::*;

pub(super) fn park_blocking_read(
    ctx: &mut dyn TrapContext,
    ops: &dyn narf_filesystem::FileOps,
) -> bool {
    if ops.block_on_input() {
        if let (Some(uctx), Some(hook)) = (
            crate::user_task::current_user_task(),
            crate::user_task::yield_hook(),
        ) {
            #[cfg(target_arch = "x86_64")]
            const SYSCALL_INSN_LEN: u64 = 2;
            #[cfg(target_arch = "aarch64")]
            const SYSCALL_INSN_LEN: u64 = 4;
            ctx.set_rip(ctx.rip().wrapping_sub(SYSCALL_INSN_LEN));
            // SAFETY: live per-task context, exclusively held in syscall.
            unsafe {
                let uc = &*uctx;
                uc.console_read_pending
                    .store(true, core::sync::atomic::Ordering::Release);
                ctx.save_user_state(uc.state.get() as *mut u8);
                *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                if narf_scheduler::stackful::user_own_stack_enabled() {
                    own_stack_block(ctx);
                    return true;
                }
                hook(uctx);
            }
        }
        return false;
    }
    park_reexecute_on_fd(
        ctx,
        ops,
        narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
    )
}

pub(super) enum TransactionalReadError {
    WouldBlock,
    User(u64),
    BadFd,
}

/// Pipe/FIFO reads must not dequeue bytes before the guarded user copy. A
/// prior range check cannot exclude a concurrent unmap; these concrete stream
/// surfaces hold the prefix stable and commit consumption only after copy.
pub(super) fn transactional_stream_read(
    ops: &dyn narf_filesystem::FileOps,
    max: usize,
    copy: impl FnMut(&[u8]) -> Result<(), u64>,
) -> Option<Result<usize, TransactionalReadError>> {
    if let Some(pipe) = ops
        .as_any()
        .and_then(|any| any.downcast_ref::<crate::pipe::PipeRead>())
    {
        return Some(pipe.read_to_user(max, copy).map_err(|error| match error {
            crate::pipe::VmspliceDrainError::WouldBlock => TransactionalReadError::WouldBlock,
            crate::pipe::VmspliceDrainError::User(errno) => TransactionalReadError::User(errno),
        }));
    }
    if let Some(fifo) = ops
        .as_any()
        .and_then(|any| any.downcast_ref::<narf_filesystem::fifo::FifoHandle>())
    {
        return Some(
            poll_blocking(fifo.read_to_user(max, copy))
                .unwrap_or(Err(narf_filesystem::fifo::VmspliceDrainError::WouldBlock))
                .map_err(|error| match error {
                    narf_filesystem::fifo::VmspliceDrainError::WouldBlock => {
                        TransactionalReadError::WouldBlock
                    }
                    narf_filesystem::fifo::VmspliceDrainError::User(errno) => {
                        TransactionalReadError::User(errno)
                    }
                    narf_filesystem::fifo::VmspliceDrainError::BadFd => {
                        TransactionalReadError::BadFd
                    }
                }),
        );
    }
    None
}

/// `read(fd, buf, count)` with Linux `vfs_read` ordering and partial progress.
pub(crate) fn sys_read(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd_num = args.arg0 as u32;
    let user_ptr = args.arg1;
    let requested = args.arg2 as usize;
    let task = current_task_id();

    let Some(endpoint) = copy_fd_endpoint(task, fd_num) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    if !endpoint.readable() {
        ctx.set_return(errno_ret(EBADF));
        return;
    }
    if let Err(errno) = validate_rw_user_range(user_ptr, requested) {
        ctx.set_return(errno_ret(errno as i64));
        return;
    }
    // `vfs_read` has no zero-count shortcut: after access_ok and
    // rw_verify_area it calls `f_op->read`, which for a directory is
    // `generic_read_dir` -> -EISDIR even for `read(dirfd, NULL, 0)`.
    if endpoint.ops.as_dir().is_some() {
        ctx.set_return(errno_ret(EISDIR));
        return;
    }
    let count = core::cmp::min(requested, LINUX_MAX_RW_COUNT);
    if count == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // AF_PACKET's read path can return protocol-specific errnos such as a
    // pending ENETDOWN. FileOps::read has no errno-preserving error carrier,
    // so run packet_recvmsg directly, as sock_read_iter does in Linux.
    if let Some(packet) = crate::socket::packet::packet_socket_of(endpoint.ops.as_ref()) {
        let mut staging = alloc::vec![0u8; count];
        match packet.packet_read(&mut staging) {
            Ok(n) => {
                // SAFETY: the complete destination range was validated above.
                if unsafe { copy_to_user(user_ptr, &staging[..n]) }.is_err() {
                    ctx.set_return(errno_ret(EFAULT));
                } else {
                    ctx.set_return(SyscallReturn::ok(n as u64));
                }
            }
            Err(e) if e == EAGAIN => {
                if endpoint.nonblocking() {
                    ctx.set_return(errno_ret(EAGAIN));
                } else if has_interrupting_signal(task) {
                    ctx.set_return(errno_ret(EINTR));
                } else if !park_blocking_read(ctx, endpoint.ops.as_ref()) {
                    ctx.set_return(SyscallReturn::ok(0));
                }
            }
            Err(e) => ctx.set_return(errno_ret(e)),
        }
        return;
    }

    if crate::pipe::is_pipe(endpoint.ops.as_ref()) {
        read_pipe_user(ctx, &endpoint, count, |offset, src, len| {
            // SAFETY: the queue retains this raw source and the scalar
            // destination range was validated before pipe lookup.
            unsafe { copy_raw_to_user(user_ptr + offset as u64, src, len) }
        });
        return;
    }

    if let Some(ret) = tty_background_access(task, endpoint.ops.as_ref(), false) {
        ctx.set_return(SyscallReturn::ok(ret as u64));
        return;
    }

    // fanotify descriptors synthesize metadata and install object fds while
    // draining their private event queue; preserve that special read surface.
    let fanotify_group = crate::mqueue::fanotify_active()
        .then(|| crate::mqueue::fanotify_instance_of(task, fd_num))
        .flatten();
    if let Some(group) = fanotify_group {
        let max = core::cmp::min(count, 64 * 1024);
        let result = fanotify_read_to_user(task, group, max, |bytes| {
            validate_fanotify_copy_range(user_ptr, bytes.len())?;
            // SAFETY: destination was range-validated above; guarded copy
            // catches a racing protection change before fds are published.
            unsafe { copy_to_user(user_ptr, bytes) }
        });
        match result {
            Ok(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            Err(errno) => ctx.set_return(errno_ret(errno as i64)),
        }
        return;
    }
    if endpoint.ops.tty_id() == Some(narf_filesystem::TTY_ID_CONSOLE) {
        note_console_reader(task);
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
    // rw_verify_area(READ, file, &f_pos, count): f_pos + count past
    // LLONG_MAX is -EINVAL (streams pass ppos == NULL and skip this).
    if !endpoint.ops.is_stream() {
        if let Err(errno) = rw_verify_area_pos(offset, requested) {
            ctx.set_return(errno_ret(errno));
            return;
        }
    }
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        let transactional = if let Some(pipe) = endpoint
            .ops
            .as_any()
            .and_then(|any| any.downcast_ref::<crate::pipe::PipeRead>())
        {
            Some(
                pipe.read_direct_to_user(user_ptr + total as u64, want)
                    .map_err(|error| match error {
                        crate::pipe::VmspliceDrainError::WouldBlock => {
                            TransactionalReadError::WouldBlock
                        }
                        crate::pipe::VmspliceDrainError::User(errno) => {
                            TransactionalReadError::User(errno)
                        }
                    }),
            )
        } else {
            let mut copied = 0usize;
            transactional_stream_read(endpoint.ops.as_ref(), want, |bytes| {
                // SAFETY: read(2) validated the original range; this guarded
                // copy catches protection changes racing that validation.
                let result = unsafe {
                    copy_to_user(user_ptr + total as u64 + copied as u64, bytes)
                };
                if result.is_ok() {
                    copied += bytes.len();
                }
                result
            })
        };
        if let Some(outcome) = transactional {
            match outcome {
                Ok(0) => break,
                Ok(read) if read <= want => {
                    total += read;
                    if read < want {
                        break;
                    }
                    continue;
                }
                Ok(_) => {
                    if total == 0 {
                        ctx.set_return(errno_ret(EINVAL));
                        return;
                    }
                    break;
                }
                Err(TransactionalReadError::User(errno)) if total == 0 => {
                    ctx.set_return(errno_ret(errno as i64));
                    return;
                }
                Err(TransactionalReadError::BadFd) if total == 0 => {
                    ctx.set_return(errno_ret(EBADF));
                    return;
                }
                Err(TransactionalReadError::WouldBlock) if total == 0 => {
                    if endpoint.nonblocking() {
                        ctx.set_return(errno_ret(EAGAIN));
                        return;
                    }
                    if has_interrupting_signal(task) {
                        ctx.set_return(errno_ret(EINTR));
                        return;
                    }
                    if park_blocking_read(ctx, endpoint.ops.as_ref()) {
                        return;
                    }
                    ctx.set_return(SyscallReturn::ok(0));
                    return;
                }
                Err(_) => break,
            }
        }
        let mut staging = alloc::vec![0u8; want];
        // Poll the read future ONCE (Pending → WouldBlock) instead of
        // spin-pumping it in `poll_blocking` when either
        //   - the description is O_NONBLOCK on a stream/char device: it must
        //     never park; or
        //   - the source is a `nonblock_read_eagain` one (pty, eventfd,
        //     timerfd, signalfd, evdev, mqueue), which answers a read at once
        //     — data or WouldBlock — so a pump only burns its iteration budget
        //     before reporting the same WouldBlock. An evdev read future is
        //     Pending-when-empty; pumping it is what once hung kwin's input
        //     loop before its event loop could present a frame.
        // Regular files keep the pump: they never EAGAIN, and their read
        // future may need several non-parking polls to fill from the page
        // cache. The empty case below then returns EAGAIN only for an
        // O_NONBLOCK description and parks until readable otherwise — Linux
        // `n_tty_read`, `eventfd_read`, `timerfd_read`, `signalfd_read` and
        // `evdev_read` all test `file->f_flags & O_NONBLOCK`.
        let poll_once_only = endpoint.ops.nonblock_read_eagain()
            || (endpoint.nonblocking() && endpoint.ops.is_stream());
        let read_fut = endpoint.ops.read(offset, &mut staging);
        let outcome = if poll_once_only {
            poll_once(read_fut).unwrap_or(Err(narf_filesystem::FsError::WouldBlock))
        } else {
            poll_blocking(read_fut).unwrap_or(Err(narf_filesystem::FsError::WouldBlock))
        };
        match outcome {
            Ok(0) => break,
            Ok(read) if read <= staging.len() => {
                // SAFETY: full destination was validated before FileOps.
                let copied = unsafe { copy_to_user(user_ptr + total as u64, &staging[..read]) };
                if let Err(errno) = copied {
                    if total == 0 {
                        ctx.set_return(errno_ret(errno as i64));
                        return;
                    }
                    break;
                }
                total += read;
                offset = offset.saturating_add(read as u64);
                if read < staging.len() {
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
                    return;
                }
                if has_interrupting_signal(task) {
                    ctx.set_return(errno_ret(EINTR));
                    return;
                }
                if park_blocking_read(ctx, endpoint.ops.as_ref()) {
                    return;
                }
                ctx.set_return(SyscallReturn::ok(0));
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
        }
    }

    if !endpoint.ops.is_stream() {
        endpoint.description.set_offset(offset);
    }
    // Mirror of the fifo wake in sys_write: draining a FIFO makes room, so a
    // writer parked on a full buffer must be re-enqueued now (see the helper).
    if total != 0 {
        wake_fifo_io_waiters(endpoint.ops.as_ref());
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
