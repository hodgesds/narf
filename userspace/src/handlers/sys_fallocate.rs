#[allow(unused_imports)]
use super::*;

/// `fallocate(fd, mode, offset, len)`.
///
/// `SYSCALL_DEFINE4(fallocate)` resolves the descriptor first (-EBADF), then
/// `vfs_fallocate` applies, in order:
///
/// ```text
///   if (offset < 0 || len <= 0) return -EINVAL;
///   ...mode validation...                     /* -EOPNOTSUPP */
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
    const ZERO_RANGE: u64 = 0x10;
    let task = current_task_id();

    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    // loff_t arguments: a negative offset or a non-positive length is a
    // caller error, distinct from "this filesystem cannot preallocate".
    if (offset as i64) < 0 || (len as i64) <= 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    if mode & !(KEEP_SIZE | PUNCH_HOLE | ZERO_RANGE) != 0
        || mode & PUNCH_HOLE != 0 && mode != PUNCH_HOLE | KEEP_SIZE
    {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // -EOPNOTSUPP
        return;
    }
    if !endpoint.writable() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    }
    match endpoint.ops.stat().mode.file_type {
        narf_filesystem::FileType::File | narf_filesystem::FileType::Block => {}
        narf_filesystem::FileType::Fifo => {
            ctx.set_return(SyscallReturn::ok((-29i64) as u64)); // -ESPIPE
            return;
        }
        narf_filesystem::FileType::Dir => {
            ctx.set_return(SyscallReturn::ok((-21i64) as u64)); // -EISDIR
            return;
        }
        _ => {
            ctx.set_return(SyscallReturn::ok((-19i64) as u64)); // -ENODEV
            return;
        }
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
        Err(narf_filesystem::FsError::Unsupported) => {
            ctx.set_return(SyscallReturn::ok((-95i64) as u64)) // -EOPNOTSUPP
        }
        Err(error) => ctx.set_return(SyscallReturn::ok((-copy_fs_errno(error)) as u64)),
    }
}
