#[allow(unused_imports)]
use super::*;

/// `splice(fd_in, off_in*, fd_out, off_out*, len, flags)` — move data
/// between two fds (at least one a pipe) without a userspace copy.
/// NARF reuses the sendfile copy core; `off_out` (only meaningful for
/// a seekable out_fd) is not honoured — pipes pass NULL.
pub(crate) fn sys_splice(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    match copy_fd_to_fd(task, a.arg0 as u32, a.arg2 as u32, a.arg1, a.arg4 as usize) {
        Some(total) => ctx.set_return(SyscallReturn::ok(total as u64)),
        None => ctx.set_return(SyscallReturn::ok((-1i64) as u64)),
    }
}
