#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_dup(ctx: &mut dyn TrapContext) {
    let oldfd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| t.duplicate(oldfd, 0, 0));
    match outcome {
        Some(Some(new_fd)) => {
            #[cfg(feature = "linux-compat")]
            crate::mqueue::duplicate_fd_path(task, oldfd, new_fd);
            ctx.set_return(SyscallReturn::ok(new_fd as u64));
        }
        // oldfd is not an open file descriptor → EBADF.
        _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
    }
}
