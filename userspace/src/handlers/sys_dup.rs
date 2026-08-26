#[allow(unused_imports)]
use super::*;

/// `dup(fd)` — `fs/file.c::SYSCALL_DEFINE1(dup)`:
///
/// ```text
///   struct file *file = fget_raw(fildes);
///   if (!file) return -EBADF;
///   ret = get_unused_fd_flags(0);          /* -EMFILE when full */
/// ```
///
/// The two failures are not interchangeable. A server that duplicates a
/// listener per connection sheds load on -EMFILE and keeps running; -EBADF
/// tells it its own descriptor bookkeeping is broken, which is a bug report,
/// not a backpressure signal. Before RLIMIT_NOFILE was enforced the table
/// simply grew, so -EMFILE could never be reported at all.
pub(crate) fn sys_dup(ctx: &mut dyn TrapContext) {
    let oldfd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let outcome = fd::with_table_alloc(task, |t| t.duplicate(oldfd, 0, 0));
    match outcome {
        Some(Ok(new_fd)) => {
            crate::mqueue::duplicate_fd_path(task, oldfd, new_fd);
            ctx.set_return(SyscallReturn::ok(new_fd as u64));
        }
        Some(Err(crate::fd::FdAllocError::TooManyFiles)) => {
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
        }
        // oldfd is not an open file descriptor → EBADF.
        _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
    }
}
