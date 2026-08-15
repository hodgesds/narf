#[allow(unused_imports)]
use super::*;

/// Linux `writev(fd, iov, iovcnt)`. Walks the user `iovec[]` and
/// writes each non-empty slice to `fd` in order, returning the
/// total byte count. Reuses `sys_write`'s per-slice copy-in +
/// FileOps path so behaviour matches a sequence of `write()`
/// calls. musl's `__stdio_write` flushes via this syscall.
///
/// Error/blocking discipline matches `sys_write` — and must: Linux
/// `do_writev` ends in the same `pipe_write` as `write(2)`, so a writev
/// into a pipe with no readers raises SIGPIPE + -EPIPE, and a writev that
/// makes no progress against a FULL pipe BLOCKS (or EAGAINs under
/// O_NONBLOCK). The old body answered EPIPE with a bare -EPERM and no
/// signal, and answered a full pipe with a 0 count that musl's stdio
/// flush loop spins on.
pub(crate) fn sys_writev(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let iov_ptr = args.arg1;
    let iovcnt = args.arg2 as usize;

    // Reasonable upper bound on the iovec count — Linux's
    // `IOV_MAX` is 1024. Reject larger to avoid trusting an
    // attacker-controlled length.
    const IOV_MAX: usize = 1024;
    if iovcnt > IOV_MAX {
        ctx.set_return(SyscallReturn::ok((-(22i64)) as u64)); // -EINVAL
        return;
    }

    // Copy the iovec array in. `struct iovec` is
    // `{ void *iov_base; size_t iov_len; }` — 16 bytes per entry.
    let iov_bytes = iovcnt.saturating_mul(16);
    // SAFETY: single-threaded syscall; AS is still active.
    let iov_buf = match unsafe { copy_from_user_vec(iov_ptr, iov_bytes) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };

    let task = current_task_id();
    // Snapshot ops + offset and DROP the fd-table lock before calling into
    // FileOps — same rule as `sys_write`: the table lock is non-reentrant,
    // and holding it across a potentially-slow write serialises CLONE_FILES
    // siblings (and self-deadlocks any FileOps that consults the table).
    let snapshot = fd::with_table(task, |t| {
        let e = t.get(fd)?;
        Some((e.ops.clone(), e.offset, e.status_flags))
    });
    let (ops, start_off, status_flags) = match snapshot {
        Some(Some(v)) => v,
        _ => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
    };
    let nonblock = status_flags & crate::fd::O_NONBLOCK != 0;
    let mut cur = start_off;
    let mut total: usize = 0;
    for i in 0..iovcnt {
        let off = i * 16;
        let base = u64::from_le_bytes(iov_buf[off..off + 8].try_into().unwrap_or([0; 8]));
        let len =
            u64::from_le_bytes(iov_buf[off + 8..off + 16].try_into().unwrap_or([0; 8])) as usize;
        if len == 0 {
            continue;
        }
        // SAFETY: single-threaded syscall; AS is still active.
        let kbuf = match unsafe { copy_from_user_vec(base, len) } {
            Ok(b) => b,
            Err(e) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
                    return;
                }
                break;
            }
        };
        let res = poll_blocking(ops.write(cur, &kbuf))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        match res {
            Ok(0) if total == 0 => {
                // No progress at all against a full pipe/FIFO with a live
                // reader (`fs/pipe.c::pipe_write` waits for room): O_NONBLOCK
                // → -EAGAIN, blocking → park + RE-EXECUTE the whole writev
                // (nothing was consumed, so a re-run is idempotent).
                if ops.write_should_block() {
                    if nonblock {
                        ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                        return;
                    }
                    if park_reexecute_on_io(ctx) {
                        return;
                    }
                }
                // Kernel-test context (no executor) or a genuine 0 count.
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            Ok(n) => {
                cur = cur.saturating_add(n as u64);
                total = total.saturating_add(n);
                if n < kbuf.len() {
                    break;
                }
            }
            // Writev into a pipe/FIFO whose readers are all gone: SIGPIPE +
            // -EPIPE (`fs/pipe.c::pipe_write`: "if (!pipe->readers) {
            // send_sig(SIGPIPE...); ret = -EPIPE; }"). Only when nothing was
            // written yet — a partial count reports the progress instead.
            Err(narf_filesystem::FsError::BrokenPipe) if total == 0 => {
                raise_signal_pending(task, 13); // SIGPIPE
                ctx.set_return(SyscallReturn::ok((-32i64) as u64)); // -EPIPE
                return;
            }
            // Wrong-direction fd (writing a pipe read end) → -EBADF, per
            // `fs/read_write.c::vfs_write`'s FMODE_WRITE check. No SIGPIPE.
            Err(narf_filesystem::FsError::BadFd) if total == 0 => {
                ctx.set_return(SyscallReturn::ok((-9i64) as u64));
                return;
            }
            Err(narf_filesystem::FsError::NoSpace) if total == 0 => {
                ctx.set_return(SyscallReturn::ok((-28i64) as u64)); // -ENOSPC
                return;
            }
            Err(narf_filesystem::FsError::QuotaExceeded) if total == 0 => {
                ctx.set_return(SyscallReturn::ok((-122i64) as u64)); // -EDQUOT
                return;
            }
            Err(_) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::invalid_op());
                    return;
                }
                break;
            }
        }
    }
    let _ = fd::with_table(task, |t| {
        if let Some(e) = t.get_mut(fd) {
            e.offset = cur;
        }
    });
    #[cfg(feature = "linux-compat")]
    if total > 0 {
        crate::mqueue::notify_modify_fd(task, fd);
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
