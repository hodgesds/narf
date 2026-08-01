#[allow(unused_imports)]
use super::*;

/// Linux `writev(fd, iov, iovcnt)`. Walks the user `iovec[]` and
/// writes each non-empty slice to `fd` in order, returning the
/// total byte count. Reuses `sys_write`'s per-slice copy-in +
/// FileOps path so behaviour matches a sequence of `write()`
/// calls. musl's `__stdio_write` flushes via this syscall.
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
        let outcome = fd::with_table(task, |t| {
            let entry = t.get_mut(fd).ok_or(9i32)?;
            let cur_off = entry.offset;
            let res = poll_blocking(entry.ops.write(cur_off, &kbuf))
                .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
            match res {
                Ok(written) => {
                    entry.offset = cur_off.saturating_add(written as u64);
                    Ok(written)
                }
                Err(narf_filesystem::FsError::NoSpace) => Err(28),
                Err(_) => Err(1),
            }
        });
        match outcome {
            Some(Ok(n)) => {
                total = total.saturating_add(n);
                if n < kbuf.len() {
                    break;
                }
            }
            Some(Err(errno)) if total == 0 => {
                ctx.set_return(SyscallReturn::ok((-errno) as u64));
                return;
            }
            _ => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::invalid_op());
                    return;
                }
                break;
            }
        }
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
