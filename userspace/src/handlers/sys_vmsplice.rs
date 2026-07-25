#[allow(unused_imports)]
use super::*;

/// `vmsplice(fd, iov, nr_segs, flags)` — gather user memory described by
/// `iov` into the pipe referenced by `fd` (the write-to-pipe direction,
/// which is the common use). Flags (arg3) are accepted but unused.
pub(crate) fn sys_vmsplice(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let fd = a.arg0 as u32;
    let iov_ptr = a.arg1;
    let nr = a.arg2 as usize;
    const IOV_MAX: usize = 1024;
    if nr > IOV_MAX {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // SAFETY: single-threaded syscall; AS active. Validates the iovec array.
    let iov_buf = match unsafe { copy_from_user_vec(iov_ptr, nr.saturating_mul(16)) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };
    let task = current_task_id();
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
        let w = fd::with_table(task, |t| {
            let entry = t.get_mut(fd).ok_or(())?;
            poll_blocking(entry.ops.write(0, &kbuf))
                .unwrap_or(Err(narf_filesystem::FsError::ReadOnly))
                .map_err(|_| ())
        });
        match w {
            Some(Ok(n)) => {
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
