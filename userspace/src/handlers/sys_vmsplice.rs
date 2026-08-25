#[allow(unused_imports)]
use super::*;

/// `vmsplice(fd, iov, nr_segs, flags)` — move pages between the pipe `fd`
/// and the user memory described by `iov`. Direction is fixed by which end
/// of the pipe `fd` names (`fs/splice.c::do_vmsplice`):
///   * the WRITE end → gather user memory INTO the pipe (`iov` is a source);
///   * the READ end  → copy queued pipe bytes OUT to user memory (`iov` is a
///     sink, i.e. `SPLICE_F_GIFT`-less SPLICE_TO_USER).
///
/// NARF distinguishes the two ends with `pipe_peek` (overridden to `Some`
/// only on the read half). The read direction is what stress-ng's vm-splice
/// stressor issues as its verification step (`vmsplice(fds[0], …)`); treating
/// every fd as a gather target used to hit `PipeRead::write`'s `EBADF` and
/// abort the loop on iteration one.
///
/// Linux entry ordering is load-bearing here: reject unknown flags, resolve
/// the fd and its access mode, import + validate the iovec, return zero for an
/// empty iterator, and only then require that the fd is a pipe. This makes the
/// combined-error cases agree with `fs/splice.c::vmsplice` rather than whichever
/// check happens to be cheapest in NARF.
pub(crate) fn sys_vmsplice(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let fd = a.arg0 as u32;
    let iov_ptr = a.arg1;
    let nr = a.arg2 as usize;
    // Linux declares flags as `unsigned int`; discard register-extension bits
    // before validating exactly as the syscall argument conversion does.
    let flags = a.arg3 as u32;
    const SPLICE_F_ALL: u32 = 0x0f; // MOVE | NONBLOCK | MORE | GIFT
    const IOV_MAX: usize = 1024;

    // fs/splice.c::vmsplice checks flags before touching the fd or iovec.
    if flags & !SPLICE_F_ALL != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    let task_id = current_task_id();
    // Linux resolves the descriptor and f_mode before importing the iovec.
    // Clone the object and mode out so no fd-table lock survives user copy or
    // I/O. O_RDWR has FMODE_WRITE and therefore selects ITER_SOURCE first.
    let resolved = fd::with_table(task_id, |t| {
        let entry = t.get(fd)?;
        Some((alloc::sync::Arc::clone(&entry.ops), t.status_flags(fd)?))
    })
    .flatten();
    let Some((ops, status_flags)) = resolved else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
        return;
    };
    // O_PATH is not O_RDONLY: Linux opens it without FMODE_READ or
    // FMODE_WRITE, so the f_mode check returns EBADF before import_iovec.
    if status_flags & crate::fd::O_PATH != 0 {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
        return;
    }
    let access_mode = status_flags & crate::fd::O_ACCMODE;
    let direction = match access_mode {
        crate::fd::O_WRONLY | crate::fd::O_RDWR => VmspliceDirection::ToPipe,
        crate::fd::O_RDONLY => VmspliceDirection::FromPipe,
        _ => {
            // No FMODE_READ or FMODE_WRITE (the Linux O_PATH shape).
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        }
    };

    // import_iovec happens only after fd/f_mode validation. Linux accepts
    // nr_segs == 0 without reading uiov, including a NULL uiov pointer.
    if nr > IOV_MAX {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let iov = if nr == 0 {
        alloc::vec::Vec::new()
    } else {
        // SAFETY: single-threaded syscall; AS active. copy_from_user_vec validates.
        match unsafe { copy_from_user_vec(iov_ptr, nr * 16) } {
            Ok(bytes) => bytes,
            Err(e) => {
                ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
                return;
            }
        }
    };
    let total_len = match validate_vmsplice_iovecs(&iov, nr) {
        Ok(total) => total,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
            return;
        }
    };
    // Linux tests iov_iter_count before vmsplice_to_{pipe,user}; consequently
    // an empty vector succeeds even when the descriptor names a regular file.
    if total_len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // get_pipe_info() lives inside vmsplice_to_{pipe,user}, after import_iovec.
    if ops.pipe_capacity().is_none() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF: not a pipe
        return;
    }
    match direction {
        VmspliceDirection::ToPipe => vmsplice_to_pipe(ctx, ops.as_ref(), &iov, nr, flags),
        VmspliceDirection::FromPipe => {
            let read_end = ops.as_any().and_then(|any| {
                any.downcast_ref::<crate::pipe::PipeRead>()
                    .map(VmspliceReadEnd::Anonymous)
                    .or_else(|| {
                        any.downcast_ref::<narf_filesystem::fifo::FifoHandle>()
                            .map(VmspliceReadEnd::Named)
                    })
            });
            if let Some(read_end) = read_end {
                vmsplice_from_pipe(ctx, read_end, &iov, nr, flags);
            } else {
                // A pipe-shaped provider without a supported read-end
                // transaction cannot satisfy SPLICE_TO_USER.
                ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            }
        }
    }
}

#[derive(Copy, Clone)]
enum VmspliceDirection {
    ToPipe,
    FromPipe,
}

#[derive(Copy, Clone)]
enum VmspliceReadEnd<'a> {
    Anonymous(&'a crate::pipe::PipeRead),
    Named(&'a narf_filesystem::fifo::FifoHandle),
}

enum VmspliceReadError {
    WouldBlock,
    User(u64),
    BadFd,
}

impl VmspliceReadEnd<'_> {
    fn copy_to_user(self, dst: u64, max: usize) -> Result<usize, VmspliceReadError> {
        match self {
            Self::Anonymous(pipe) => pipe
                .vmsplice_to_user(dst, max)
                .map_err(|error| match error {
                    crate::pipe::VmspliceDrainError::WouldBlock => VmspliceReadError::WouldBlock,
                    crate::pipe::VmspliceDrainError::User(errno) => VmspliceReadError::User(errno),
                }),
            Self::Named(fifo) => fifo
                .vmsplice_to_user(max, |bytes| {
                    // SAFETY: validate_vmsplice_iovecs accepted this complete
                    // destination range. The guarded copy catches a racing
                    // unmap/protection change while the FIFO transaction still
                    // owns, but has not consumed, the queue prefix.
                    unsafe { copy_to_user(dst, bytes) }
                })
                .map_err(|error| match error {
                    narf_filesystem::fifo::VmspliceDrainError::WouldBlock => {
                        VmspliceReadError::WouldBlock
                    }
                    narf_filesystem::fifo::VmspliceDrainError::User(errno) => {
                        VmspliceReadError::User(errno)
                    }
                    narf_filesystem::fifo::VmspliceDrainError::BadFd => VmspliceReadError::BadFd,
                }),
        }
    }
}

/// Mirror import_iovec's per-element validation before pipe readiness is
/// sampled. In particular a full nonblocking pipe plus an invalid payload
/// range is EFAULT, not EAGAIN. Zero-length elements do not touch iov_base.
fn validate_vmsplice_iovecs(iov_buf: &[u8], nr: usize) -> Result<usize, u64> {
    let mut total = 0usize;
    for i in 0..nr {
        let o = i * 16;
        let base = u64::from_le_bytes(iov_buf[o..o + 8].try_into().unwrap_or([0; 8]));
        let len_raw = u64::from_le_bytes(iov_buf[o + 8..o + 16].try_into().unwrap_or([0; 8]));
        // copy_iovec_from_user reads iov_len through ssize_t and rejects a
        // value with the sign bit set before initializing the iterator.
        if len_raw > isize::MAX as u64 {
            return Err(EINVAL_CODE);
        }
        let len = len_raw as usize;
        if len == 0 {
            continue;
        }
        validate_user_range(base, len)?;
        total = total.saturating_add(len);
    }
    Ok(total)
}

/// Gather user memory described by `iov` INTO the pipe write end `fd`.
fn vmsplice_to_pipe(
    ctx: &mut dyn TrapContext,
    ops: &dyn narf_filesystem::FileOps,
    iov_buf: &[u8],
    nr: usize,
    flags: u32,
) {
    const SPLICE_F_NONBLOCK: u32 = 0x2;
    // Full-pipe check BEFORE gathering anything: a blocking vmsplice into a
    // full pipe must wait for room (`fs/splice.c::vmsplice_to_pipe` →
    // wait_for_space), and parking here — before a single byte is written —
    // keeps the re-executed syscall idempotent (nothing has been consumed).
    // `SPLICE_F_NONBLOCK` short-circuits to -EAGAIN instead.
    let pipe_full =
        ops.poll_readiness() & narf_filesystem::POLL_OUT == 0 && ops.write_should_block();
    if pipe_full {
        if flags & SPLICE_F_NONBLOCK != 0 {
            ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
            return;
        }
        if park_reexecute_on_fd(
            ctx,
            ops,
            narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
        ) {
            return;
        }
        // Kernel-test context (no executor): fall through to a best-effort copy.
    }
    let mut total: usize = 0;
    for i in 0..nr {
        let o = i * 16;
        let base = u64::from_le_bytes(iov_buf[o..o + 8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(iov_buf[o + 8..o + 16].try_into().unwrap_or([0; 8])) as usize;
        if len == 0 {
            continue;
        }
        // SAFETY: `base` is a user VA; copy_from_user_vec validates it.
        let kbuf = match unsafe { copy_from_user_vec(base, len) } {
            Ok(b) => b,
            Err(_) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                    return;
                }
                break;
            }
        };
        let w =
            poll_blocking(ops.write(0, &kbuf)).unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        match w {
            Ok(0) if total == 0 && ops.write_should_block() => {
                // The pipe may have become full after the readiness sample.
                // No byte was committed, so the syscall is still safe to
                // return EAGAIN or park and re-execute.
                if flags & SPLICE_F_NONBLOCK != 0 {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                if park_reexecute_on_fd(
                    ctx,
                    ops,
                    narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
                ) {
                    return;
                }
                break;
            }
            Ok(n) => {
                total = total.saturating_add(n);
                if n < len {
                    break;
                }
            }
            Err(narf_filesystem::FsError::BrokenPipe) => {
                if total == 0 {
                    raise_signal_pending(current_task_id(), 13); // SIGPIPE
                    ctx.set_return(SyscallReturn::ok((-32i64) as u64)); // EPIPE
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                if flags & SPLICE_F_NONBLOCK != 0 {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                if park_reexecute_on_fd(
                    ctx,
                    ops,
                    narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR,
                ) {
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::BadFd) | Err(narf_filesystem::FsError::ReadOnly) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
                    return;
                }
                break;
            }
            Err(_) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-5i64) as u64)); // EIO
                    return;
                }
                break;
            }
        }
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}

/// Copy queued bytes OUT of the pipe read end `fd` into the user memory
/// described by `iov` (`fs/splice.c` SPLICE_TO_USER). Stops at the first
/// segment the pipe can't fill (a short/empty read), returning the running
/// byte count — exactly Linux's iovec-at-a-time drain.
fn vmsplice_from_pipe(
    ctx: &mut dyn TrapContext,
    pipe: VmspliceReadEnd<'_>,
    iov_buf: &[u8],
    nr: usize,
    flags: u32,
) {
    const SPLICE_F_NONBLOCK: u32 = 0x2;
    let mut total: usize = 0;
    for i in 0..nr {
        let o = i * 16;
        let base = u64::from_le_bytes(iov_buf[o..o + 8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(iov_buf[o + 8..o + 16].try_into().unwrap_or([0; 8])) as usize;
        if len == 0 {
            continue;
        }
        // The pipe owns the observe/copy/consume transaction: a failed or
        // racing user copy must not discard bytes already removed from the
        // queue.
        let n = match pipe.copy_to_user(base, len) {
            Ok(n) => n,
            Err(VmspliceReadError::WouldBlock) => {
                // Empty-but-open pipe. Before any byte is consumed the drain is
                // idempotent, so EAGAIN (nonblock) or park+re-exec is safe.
                if total > 0 {
                    break;
                }
                if flags & SPLICE_F_NONBLOCK != 0 {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                let ops: &dyn narf_filesystem::FileOps = match pipe {
                    VmspliceReadEnd::Anonymous(pipe) => pipe,
                    VmspliceReadEnd::Named(fifo) => fifo,
                };
                if park_reexecute_on_fd(
                    ctx,
                    ops,
                    narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
                ) {
                    return;
                }
                // Kernel-test context (no executor): report the 0-byte drain.
                break;
            }
            Err(VmspliceReadError::User(errno)) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                    return;
                }
                break;
            }
            Err(VmspliceReadError::BadFd) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
                    return;
                }
                break;
            }
        };
        if n == 0 {
            break; // EOF (writer gone, pipe empty)
        }
        total = total.saturating_add(n);
        if n < len {
            break; // pipe drained short — stop, matching Linux
        }
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
