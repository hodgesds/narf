#[allow(unused_imports)]
use super::*;

/// `readahead(fd, offset, count)` — page-cache populate hint.
///
/// `mm/readahead.c::ksys_readahead`:
///
/// ```text
///   if (fd_empty(f))                    return -EBADF;
///   if (!(file->f_mode & FMODE_READ))   return -EBADF;
///   if (!file->f_mapping->a_ops)        return -EINVAL;
///   if (!S_ISREG(..) && !S_ISBLK(..))   return -EINVAL;
/// ```
///
/// NARF's in-memory filesystems need no readahead, so a valid call is a no-op
/// success. The checks still matter: readahead(2) is documented to work only
/// where readahead is possible, and -EINVAL on a pipe or socket is how a
/// caller learns its optimisation does not apply there rather than believing
/// it took effect.
pub(crate) fn sys_readahead(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();

    let Some(endpoint) = copy_fd_endpoint(task, fd) else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    if !endpoint.readable() {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    }
    match endpoint.ops.stat().mode.file_type {
        narf_filesystem::FileType::File | narf_filesystem::FileType::Block => {
            ctx.set_return(SyscallReturn::ok(0))
        }
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // -EINVAL
    }
}
