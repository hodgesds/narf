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
/// Flags: `SPLICE_F_NONBLOCK` short-circuits a would-block (full pipe on the
/// gather side, empty pipe on the drain side) to `-EAGAIN`; the other flags
/// are accepted and ignored (NARF copies rather than moving pages by ref).
pub(crate) fn sys_vmsplice(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let fd = a.arg0 as u32;
    let iov_ptr = a.arg1;
    let nr = a.arg2 as usize;
    let flags = a.arg3;
    const IOV_MAX: usize = 1024;
    if nr > IOV_MAX {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // Validate + read the iovec array BEFORE resolving the fd direction, so a
    // bad iovec pointer reports -EFAULT rather than being masked by an fd
    // verdict (the historical NARF order; also spares re-reading it per path).
    // SAFETY: single-threaded syscall; AS active. copy_from_user_vec validates.
    let iov = match unsafe { copy_from_user_vec(iov_ptr, nr.saturating_mul(16)) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };
    let task_id = current_task_id();
    // Resolve and clone the file object without retaining the fd-table lock
    // across I/O or a guarded user copy.  vmsplice requires a pipe; accepting
    // an arbitrary writable file here would violate its fd contract.
    let ops = fd::with_table(task_id, |t| {
        t.get(fd).map(|e| alloc::sync::Arc::clone(&e.ops))
    })
    .flatten();
    let Some(ops) = ops else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
        return;
    };
    if ops.pipe_capacity().is_none() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF: not a pipe
        return;
    }
    if let Some(read_end) = ops
        .as_any()
        .and_then(|any| any.downcast_ref::<crate::pipe::PipeRead>())
    {
        vmsplice_from_pipe(ctx, read_end, &iov, nr, flags);
    } else {
        vmsplice_to_pipe(ctx, ops.as_ref(), &iov, nr, flags);
    }
}

/// Gather user memory described by `iov` INTO the pipe write end `fd`.
fn vmsplice_to_pipe(
    ctx: &mut dyn TrapContext,
    ops: &dyn narf_filesystem::FileOps,
    iov_buf: &[u8],
    nr: usize,
    flags: u64,
) {
    const SPLICE_F_NONBLOCK: u64 = 0x2;
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
        let w = poll_blocking(ops.write(0, &kbuf))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        match w {
            Ok(n) => {
                total = total.saturating_add(n);
                if n < len {
                    break;
                }
            }
            _ => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
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
    pipe: &crate::pipe::PipeRead,
    iov_buf: &[u8],
    nr: usize,
    flags: u64,
) {
    const SPLICE_F_NONBLOCK: u64 = 0x2;
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
        let n = match pipe.vmsplice_to_user(base, len) {
            Ok(n) => n,
            Err(crate::pipe::VmspliceDrainError::WouldBlock) => {
                // Empty-but-open pipe. Before any byte is consumed the drain is
                // idempotent, so EAGAIN (nonblock) or park+re-exec is safe.
                if total > 0 {
                    break;
                }
                if flags & SPLICE_F_NONBLOCK != 0 {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                if park_reexecute_on_fd(
                    ctx,
                    pipe,
                    narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
                ) {
                    return;
                }
                // Kernel-test context (no executor): report the 0-byte drain.
                break;
            }
            Err(crate::pipe::VmspliceDrainError::User(errno)) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
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
