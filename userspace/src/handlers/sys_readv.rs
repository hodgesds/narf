#[allow(unused_imports)]
use super::*;

/// `readv(fd, iov, iovcnt)` — vectored read at the current file offset,
/// advancing it (the position-tracking counterpart to `writev`).
///
/// Blocking discipline matches `sys_read` — and must: Linux `do_readv` ends
/// in the same `pipe_read` as `read(2)`, so a readv on an EMPTY pipe whose
/// writer is still open BLOCKS (or EAGAINs under O_NONBLOCK). The old body
/// returned the transient 0 straight to userspace, a spurious EOF: musl's
/// `__stdio_read` fills stdio buffers via readv, so every musl `fread` from
/// a momentarily-empty pipe ended the stream — the same lost-data class as
/// the sendfile/copy_file_range transient-EOF bugs.
pub(crate) fn sys_readv(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let iov_ptr = args.arg1;
    let iovcnt = args.arg2 as usize;
    const IOV_MAX: usize = 1024;
    if iovcnt > IOV_MAX {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // SAFETY: single-threaded syscall; AS active. Validates the iovec array.
    let iov_buf = match unsafe { copy_from_user_vec(iov_ptr, iovcnt.saturating_mul(16)) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };
    let task = current_task_id();
    // Snapshot ops + offset and DROP the fd-table lock before calling into
    // FileOps — same rule as `sys_read`: holding the non-reentrant table
    // lock across a FileOps call self-deadlocks any file whose read
    // consults the fd table (/proc fdinfo), and serialises CLONE_FILES
    // siblings behind a slow read.
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
        let o = i * 16;
        let base = u64::from_le_bytes(iov_buf[o..o + 8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(iov_buf[o + 8..o + 16].try_into().unwrap_or([0; 8])) as usize;
        if len == 0 {
            continue;
        }
        let mut kbuf = alloc::vec![0u8; len];
        let res = poll_blocking(ops.read(cur, &mut kbuf)).unwrap_or(Ok(0));
        // The explicit would-block signal. `Ok(0)` is EOF, so a consumer
        // cannot accidentally turn an empty-but-open stream into a close.
        let res = match res {
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                if nonblock {
                    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
                    return;
                }
                if park_reexecute_on_fd(
                    ctx,
                    ops.as_ref(),
                    narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
                ) {
                    return;
                }
                // No executor (kernel-test context): fall through as a dry read.
                Ok(0)
            }
            // Bytes already gathered: stop here and report them, exactly as a
            // short read would.
            Err(narf_filesystem::FsError::WouldBlock) => break,
            other => other,
        };
        match res {
            Ok(0) if total == 0 => {
                // A successful zero-byte read is genuine EOF.
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            Ok(n) => {
                // SAFETY: `base` is the user iovec destination; copy_to_user
                // validates the `n`-byte write.
                if n > 0 && unsafe { copy_to_user(base, &kbuf[..n]) }.is_err() {
                    if total == 0 {
                        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
                        return;
                    }
                    break;
                }
                cur = cur.saturating_add(n as u64);
                total = total.saturating_add(n);
                if n < len {
                    break; // short read / EOF after data — return what we have
                }
            }
            // Wrong-direction fd (reading a pipe write end) → -EBADF, per
            // `fs/read_write.c::vfs_read`'s FMODE_READ check.
            Err(narf_filesystem::FsError::BadFd) if total == 0 => {
                ctx.set_return(SyscallReturn::ok((-9i64) as u64));
                return;
            }
            Err(_) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-1i64) as u64));
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
    ctx.set_return(SyscallReturn::ok(total as u64));
}
