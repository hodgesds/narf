#[allow(unused_imports)]
use super::*;

/// `fallocate(fd, mode, offset, len)`.
///
/// `SYSCALL_DEFINE4(fallocate)` resolves the descriptor first (-EBADF), then
/// `vfs_fallocate` applies, in order:
///
/// ```text
///   if (offset < 0 || len <= 0) return -EINVAL;
///   if (mode & ~(FALLOC_FL_MODE_MASK | FALLOC_FL_KEEP_SIZE)) return -EOPNOTSUPP;
///   switch (mode & FALLOC_FL_MODE_MASK) {     /* modes are exclusive */
///   case ALLOCATE_RANGE: case UNSHARE_RANGE: case ZERO_RANGE: break;
///   case PUNCH_HOLE: if (!(mode & KEEP_SIZE)) return -EOPNOTSUPP; break;
///   case COLLAPSE_RANGE: case INSERT_RANGE: case WRITE_ZEROES:
///           if (mode & KEEP_SIZE) return -EOPNOTSUPP; break;
///   default: return -EOPNOTSUPP;
///   }
///   if (!(file->f_mode & FMODE_WRITE)) return -EBADF;
///   if (S_ISFIFO(...)) return -ESPIPE;
///   if (S_ISDIR(...)) return -EISDIR;
///   if (!S_ISREG(...) && !S_ISBLK(...)) return -ENODEV;
/// ```
///
/// The old code answered a closed fd with the `-1` sentinel (EPERM) and a
/// zero length with EOPNOTSUPP, so `posix_fallocate` — which maps EOPNOTSUPP
/// to "fall back to writing zeroes" — took the slow path for what is really
/// a caller bug.
pub(crate) fn sys_fallocate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let mode = args.arg1;
    let offset = args.arg2;
    let len = args.arg3;
    const KEEP_SIZE: u64 = 0x01;
    const PUNCH_HOLE: u64 = 0x02;
    const COLLAPSE_RANGE: u64 = 0x08;
    const ZERO_RANGE: u64 = 0x10;
    const INSERT_RANGE: u64 = 0x20;
    const UNSHARE_RANGE: u64 = 0x40;
    const WRITE_ZEROES: u64 = 0x80;
    const MODE_MASK: u64 =
        PUNCH_HOLE | COLLAPSE_RANGE | ZERO_RANGE | INSERT_RANGE | UNSHARE_RANGE | WRITE_ZEROES;
    let task = current_task_id();

    // `fdget`: an O_PATH descriptor is -EBADF before any argument check.
    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    let offset_signed = offset as i64;
    let len_signed = len as i64;
    // loff_t arguments: a negative offset or a non-positive length is a
    // caller error, distinct from "this filesystem cannot preallocate".
    if offset_signed < 0 || len_signed <= 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // VFS-level mode validation only. COLLAPSE/INSERT/UNSHARE/WRITE_ZEROES
    // are VALID here — a filesystem that cannot do them answers -EOPNOTSUPP
    // from `f_op->fallocate`, i.e. only after the fd-mode and file-type
    // checks below. Rejecting them up front reported EOPNOTSUPP where Linux
    // reports EBADF (read-only fd) or ESPIPE (pipe).
    let mode_ok = mode & !(MODE_MASK | KEEP_SIZE) == 0
        && match mode & MODE_MASK {
            0 | UNSHARE_RANGE | ZERO_RANGE => true,
            PUNCH_HOLE => mode & KEEP_SIZE != 0,
            COLLAPSE_RANGE | INSERT_RANGE | WRITE_ZEROES => mode & KEEP_SIZE == 0,
            _ => false,
        };
    if !mode_ok {
        ctx.set_return(errno_ret(EOPNOTSUPP));
        return;
    }
    if !endpoint.writable() {
        ctx.set_return(errno_ret(EBADF));
        return;
    }
    let iflags = endpoint.ops.inode_flags();
    if iflags & narf_filesystem::FS_IMMUTABLE_FL != 0
        || ((mode & !KEEP_SIZE != 0) && iflags & narf_filesystem::FS_APPEND_FL != 0)
    {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    match endpoint.ops.stat().mode.file_type {
        narf_filesystem::FileType::File | narf_filesystem::FileType::Block => {}
        narf_filesystem::FileType::Fifo => {
            ctx.set_return(errno_ret(ESPIPE));
            return;
        }
        narf_filesystem::FileType::Dir => {
            ctx.set_return(errno_ret(EISDIR));
            return;
        }
        _ => {
            ctx.set_return(errno_ret(ENODEV));
            return;
        }
    }
    // `fs/open.c::vfs_fallocate`: check for wraparound (`if (check_add_overflow(offset, len, &sum)) return -EFBIG;`).
    if offset_signed.checked_add(len_signed).is_none() {
        ctx.set_return(errno_ret(EFBIG));
        return;
    }
    let target_end = offset.saturating_add(len);
    let outcome = (|| -> Result<(), narf_filesystem::FsError> {
        let ops = endpoint.ops.clone();
        match poll_blocking(ops.fallocate(mode as u32, offset, len)) {
            Some(Ok(())) => return Ok(()),
            Some(Err(narf_filesystem::FsError::Unsupported)) | None => {}
            Some(Err(error)) => return Err(error),
        }
        if mode != 0 && mode != FALLOC_FL_ZERO_RANGE {
            return Err(narf_filesystem::FsError::Unsupported);
        }
        let cur_size = ops.stat().size;
        // Always ensure size >= offset + len. truncate handles
        // grow + zero-fill.
        if target_end > cur_size
            && poll_blocking(ops.truncate(target_end))
                .and_then(|r| r.ok())
                .is_none()
        {
            return Err(narf_filesystem::FsError::NoSpace);
        }
        if mode == FALLOC_FL_ZERO_RANGE && len > 0 && offset < cur_size {
            // Zero existing bytes in [offset, min(target_end, old size)].
            // We do this in 4-KiB chunks of zeros via a fresh write.
            let zero_end = core::cmp::min(target_end, cur_size);
            let mut cur = offset;
            let chunk = [0u8; 4096];
            while cur < zero_end {
                let span = core::cmp::min(zero_end - cur, chunk.len() as u64) as usize;
                let n = poll_blocking(ops.write(cur, &chunk[..span]))
                    .and_then(|r| r.ok())
                    .unwrap_or(0);
                if n == 0 {
                    break;
                }
                cur += n as u64;
            }
        }
        Ok(())
    })();
    match outcome {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(narf_filesystem::FsError::Unsupported) => ctx.set_return(errno_ret(EOPNOTSUPP)),
        Err(error) => ctx.set_return(errno_ret(copy_fs_errno(error))),
    }
}
