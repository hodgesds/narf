#[allow(unused_imports)]
use super::*;

/// `pwrite64(fd, buf, count, offset)` with `fs/read_write.c::ksys_pwrite64`
/// error ordering — the mirror of `sys_pread64`:
/// negative offset -EINVAL, then -EBADF for a closed fd, then -ESPIPE for a
/// stream, then `vfs_write`'s FMODE_WRITE (-EBADF) / `access_ok` (-EFAULT).
/// Write failures propagate the filesystem's errno instead of the old `-1`
/// sentinel, which surfaced to userspace as EPERM.
pub(crate) fn sys_pwrite64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1;
    let requested = args.arg2 as usize;
    let offset = args.arg3;

    if (offset as i64) < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let task = current_task_id();
    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    {
        use narf_filesystem::FileType;
        let ty = endpoint.ops.stat().mode.file_type;
        if ty == FileType::Fifo || ty == FileType::Socket {
            ctx.set_return(errno_ret(ESPIPE));
            return;
        }
    }
    if !endpoint.writable() {
        ctx.set_return(errno_ret(EBADF));
        return;
    }
    if let Err(errno) = validate_rw_user_range(ptr, requested) {
        ctx.set_return(errno_ret(errno as i64));
        return;
    }
    let count = core::cmp::min(requested, LINUX_MAX_RW_COUNT);
    if count == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Bounded chunks, as in `sys_write` — see the note in `sys_pread64` for
    // why a single copy the size of the request is not an option.
    const CHUNK: usize = 64 * 1024;
    let mut total = 0usize;
    let mut offset = offset;
    // RLIMIT_FSIZE against the EXPLICIT offset — pwrite never appends, so
    // there is no i_size to consult.
    let count = match fsize_check_write(task, offset, count, || endpoint.ops.stat().mode.file_type == narf_filesystem::FileType::File) {
        Ok(c) => c,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        // SAFETY: the complete source range passed validate_rw_user_range;
        // each bounded guarded copy still catches a racing unmap.
        let payload = match unsafe { copy_from_user_vec(ptr + total as u64, want) } {
            Ok(bytes) => bytes,
            Err(errno) => {
                if total == 0 {
                    ctx.set_return(errno_ret(errno as i64));
                    return;
                }
                break;
            }
        };
        let outcome = poll_blocking(endpoint.ops.write(offset, &payload))
            .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
        let written = match outcome {
            Ok(0) => break,
            Ok(n) if n <= payload.len() => n,
            Ok(_) => {
                if total == 0 {
                    ctx.set_return(errno_ret(EINVAL));
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                ctx.set_return(errno_ret(EAGAIN));
                return;
            }
            Err(narf_filesystem::FsError::WouldBlock) => break,
            Err(narf_filesystem::FsError::BrokenPipe) => {
                raise_signal_pending(task, 13); // SIGPIPE even after a prefix
                if total == 0 {
                    ctx.set_return(errno_ret(EPIPE));
                    return;
                }
                break;
            }
            Err(error) => {
                if total == 0 {
                    ctx.set_return(errno_ret(copy_fs_errno(error)));
                    return;
                }
                break;
            }
        };
        total += written;
        offset = offset.saturating_add(written as u64);
        if written < payload.len() {
            break;
        }
    }

    if total != 0 {
        crate::mqueue::notify_modify_fd(task, fd);
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
