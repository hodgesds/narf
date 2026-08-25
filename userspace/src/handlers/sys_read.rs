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
    copy: impl Fn(&[u8]) -> Result<(), u64>,
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
            fifo.vmsplice_to_user(max, copy)
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
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    };
    if !endpoint.readable() {
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

    #[cfg(feature = "linux-compat")]
    if let Some(ret) = tty_background_access(task, fd_num, false) {
        ctx.set_return(SyscallReturn::ok(ret as u64));
        return;
    }

    // fanotify descriptors synthesize metadata and install object fds while
    // draining their private event queue; preserve that special read surface.
    #[cfg(feature = "linux-compat")]
    let fanotify_group = crate::mqueue::fanotify_active()
        .then(|| crate::mqueue::fanotify_instance_of(task, fd_num))
        .flatten();
    #[cfg(feature = "linux-compat")]
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
            Err(errno) => ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64)),
        }
        return;
    }
    note_console_reader(task);

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
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        if let Some(outcome) = transactional_stream_read(endpoint.ops.as_ref(), want, |bytes| {
            // SAFETY: read(2) validated the original range; this guarded
            // copy catches protection changes racing that validation.
            unsafe { copy_to_user(user_ptr + total as u64, bytes) }
        }) {
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
                        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                        return;
                    }
                    break;
                }
                Err(TransactionalReadError::User(errno)) if total == 0 => {
                    ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                    return;
                }
                Err(TransactionalReadError::BadFd) if total == 0 => {
                    ctx.set_return(SyscallReturn::ok((-9i64) as u64));
                    return;
                }
                Err(TransactionalReadError::WouldBlock) if total == 0 => {
                    if endpoint.nonblocking() || endpoint.ops.nonblock_read_eagain() {
                        ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                        return;
                    }
                    if has_interrupting_signal(task) {
                        ctx.set_return(SyscallReturn::ok((-4i64) as u64));
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
        let outcome = poll_blocking(endpoint.ops.read(offset, &mut staging))
            .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
        match outcome {
            Ok(0) => break,
            Ok(read) if read <= staging.len() => {
                // SAFETY: full destination was validated before FileOps.
                let copied = unsafe { copy_to_user(user_ptr + total as u64, &staging[..read]) };
                if let Err(errno) = copied {
                    if total == 0 {
                        ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
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
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                if endpoint.nonblocking() || endpoint.ops.nonblock_read_eagain() {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                if has_interrupting_signal(task) {
                    ctx.set_return(SyscallReturn::ok((-4i64) as u64));
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
    ctx.set_return(SyscallReturn::ok(total as u64));
}
