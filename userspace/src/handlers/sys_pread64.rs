#[allow(unused_imports)]
use super::*;

/// `pread64(fd, buf, count, offset)` with `fs/read_write.c::ksys_pread64`
/// error ordering:
///
/// ```text
///   if (pos < 0) return -EINVAL;
///   f = fdget(fd); if (!fd_file(f)) return -EBADF;
///   ret = -ESPIPE; if (f->f_mode & FMODE_PREAD) ret = vfs_read(...);
/// ```
///
/// `vfs_read` then checks FMODE_READ (-EBADF) before `access_ok` (-EFAULT),
/// so a zero-length pread on a closed or write-only fd is still an error
/// rather than a 0-byte success. Read failures propagate the filesystem's
/// errno; the old blanket `-1` sentinel reached userspace as EPERM, which
/// no caller of pread(2) can interpret.
pub(crate) fn sys_pread64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1;
    let requested = args.arg2 as usize;
    let offset = args.arg3;

    // loff_t is signed: a negative offset is rejected before the fd lookup.
    if (offset as i64) < 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let task = current_task_id();
    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    // pread(2) on a pipe/FIFO/socket is -ESPIPE: those file types never get
    // FMODE_PREAD, so `ksys_pread64` returns its initial -ESPIPE without
    // consuming any bytes "at an offset".
    {
        use narf_filesystem::FileType;
        let ty = endpoint.ops.stat().mode.file_type;
        if ty == FileType::Fifo || ty == FileType::Socket {
            ctx.set_return(SyscallReturn::ok((-29i64) as u64)); // -ESPIPE
            return;
        }
    }
    if !endpoint.readable() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    }
    if let Err(errno) = validate_rw_user_range(ptr, requested) {
        ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
        return;
    }
    let count = core::cmp::min(requested, LINUX_MAX_RW_COUNT);
    if count == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Stage the transfer in bounded chunks, exactly as `sys_read` does.
    // `validate_rw_user_range` deliberately skips NARF's generic 16-MiB
    // single-copy cap so that a large request is not rejected outright — but
    // that only works if the handler then honours the cap by chunking. A
    // single `vec![0u8; count]` for a MAX_RW_COUNT-sized pread would ask the
    // kernel heap for 2 GiB and then fail the copy on the 16-MiB limit,
    // where Linux transfers the whole thing.
    const CHUNK: usize = 64 * 1024;
    let mut total = 0usize;
    let mut offset = offset;
    let mut staging = alloc::vec![0u8; core::cmp::min(CHUNK, count)];
    while total < count {
        let want = core::cmp::min(CHUNK, count - total);
        let outcome = poll_blocking(endpoint.ops.read(offset, &mut staging[..want]))
            .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
        let read = match outcome {
            Ok(0) => break,
            Ok(n) if n <= want => n,
            // A FileOps that claims more bytes than the buffer holds is a
            // driver bug, not a user error; Linux's iterators cap at the
            // iov length.
            Ok(_) => {
                if total == 0 {
                    ctx.set_return(SyscallReturn::ok((-22i64) as u64));
                    return;
                }
                break;
            }
            Err(narf_filesystem::FsError::WouldBlock) if total == 0 => {
                ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
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
        };
        // SAFETY: the destination passed validate_rw_user_range above; the
        // guarded copy still catches a protection change racing it.
        if let Err(errno) = unsafe { copy_to_user(ptr + total as u64, &staging[..read]) } {
            if total == 0 {
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                return;
            }
            break;
        }
        total += read;
        offset = offset.saturating_add(read as u64);
        if read < want {
            break; // short read / EOF
        }
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
