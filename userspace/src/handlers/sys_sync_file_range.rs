#[allow(unused_imports)]
use super::*;

/// `sync_file_range(fd, offset, nbytes, flags)` — flush a byte range.
///
/// `fs/sync.c::ksys_sync_file_range` resolves the fd (-EBADF), then
/// `sync_file_range` applies, in order:
///
/// ```text
///   if (flags & ~VALID_FLAGS)   goto out;   /* -EINVAL */
///   endbyte = offset + nbytes;
///   if ((s64)offset < 0)        goto out;   /* -EINVAL */
///   if ((s64)endbyte < 0)       goto out;   /* -EINVAL */
///   if (endbyte < offset)       goto out;   /* -EINVAL */
///   ...
///   if (!S_ISREG && !S_ISBLK && !S_ISDIR && !S_ISLNK) return -ESPIPE;
/// ```
///
/// NARF's filesystems are always coherent, so a valid range is a no-op
/// success. Validating the arguments anyway is what separates "there was
/// nothing to flush" from "you asked for something impossible": a caller
/// passing a negative offset or an unknown flag has a bug, and silently
/// returning 0 hides it behind an apparently successful flush.
pub(crate) fn sys_sync_file_range(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let offset = args.arg1;
    let nbytes = args.arg2;
    let flags = args.arg3;
    const SYNC_FILE_RANGE_WAIT_BEFORE: u64 = 1;
    const SYNC_FILE_RANGE_WRITE: u64 = 2;
    const SYNC_FILE_RANGE_WAIT_AFTER: u64 = 4;
    const VALID_FLAGS: u64 =
        SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    let task = current_task_id();

    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    let einval = SyscallReturn::ok((-22i64) as u64);
    if flags & !VALID_FLAGS != 0 {
        ctx.set_return(einval);
        return;
    }
    let endbyte = offset.wrapping_add(nbytes);
    if (offset as i64) < 0 || (endbyte as i64) < 0 || endbyte < offset {
        ctx.set_return(einval);
        return;
    }
    // A pipe or socket has no page cache to write back.
    use narf_filesystem::FileType;
    match endpoint.ops.stat().mode.file_type {
        FileType::File | FileType::Block | FileType::Dir | FileType::Symlink => {
            ctx.set_return(SyscallReturn::ok(0))
        }
        _ => ctx.set_return(SyscallReturn::ok((-29i64) as u64)), // -ESPIPE
    }
}
