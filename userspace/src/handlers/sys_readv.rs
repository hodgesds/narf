#[allow(unused_imports)]
use super::*;

/// `readv(fd, iov, iovcnt)` — vectored read at the current file offset,
/// advancing it (the position-tracking counterpart to `writev`).
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
    let mut total: usize = 0;
    for i in 0..iovcnt {
        let o = i * 16;
        let base = u64::from_le_bytes(iov_buf[o..o + 8].try_into().unwrap_or([0; 8]));
        let len = u64::from_le_bytes(iov_buf[o + 8..o + 16].try_into().unwrap_or([0; 8])) as usize;
        if len == 0 {
            continue;
        }
        let mut kbuf = alloc::vec![0u8; len];
        let outcome = fd::with_table(task, |t| {
            let entry = t.get_mut(fd).ok_or(())?;
            let cur = entry.offset;
            let res = poll_blocking(entry.ops.read(cur, &mut kbuf)).unwrap_or(Ok(0));
            match res {
                Ok(n) => {
                    entry.offset = cur.saturating_add(n as u64);
                    Ok(n)
                }
                Err(_) => Err(()),
            }
        });
        match outcome {
            Some(Ok(n)) => {
                // SAFETY: `base` is the user iovec destination; copy_to_user
                // validates the `n`-byte write.
                let _ = unsafe { copy_to_user(base, &kbuf[..n]) };
                total = total.saturating_add(n);
                if n < len {
                    break; // short read / EOF
                }
            }
            _ => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-1i64) as u64));
                    return;
                }
                break;
            }
        }
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
