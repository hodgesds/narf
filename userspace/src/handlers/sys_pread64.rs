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

    let mut kbuf = alloc::vec![0u8; count];
    let outcome = poll_blocking(endpoint.ops.read(offset, &mut kbuf))
        .unwrap_or(Err(narf_filesystem::FsError::WouldBlock));
    match outcome {
        Ok(n) if n <= kbuf.len() => {
            // SAFETY: the destination passed validate_rw_user_range above; the
            // guarded copy still catches a protection change racing it.
            if let Err(errno) = unsafe { copy_to_user(ptr, &kbuf[..n]) } {
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(n as u64));
            }
        }
        // A FileOps that claims more bytes than the buffer holds is a driver
        // bug, not a user error; Linux's iterators cap at the iov length.
        Ok(_) => ctx.set_return(SyscallReturn::ok((-22i64) as u64)),
        Err(narf_filesystem::FsError::WouldBlock) => {
            ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        }
        Err(error) => ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64)),
    }
}
