#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_dup(ctx: &mut dyn TrapContext) {
    let oldfd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(oldfd)?;
        // Clone the Arc + reset offset; keep flags clear (fcntl/dup3
        // can stamp FD_CLOEXEC after).
        let clone = crate::fd::FdEntry {
            ops: entry.ops.clone(),
            offset: 0,
            flags: 0,
            status_flags: 0,
        };
        Some(t.open(clone))
    });
    match outcome {
        Some(Some(new_fd)) => {
            #[cfg(feature = "linux-compat")]
            crate::mqueue::duplicate_fd_path(task, oldfd, new_fd);
            ctx.set_return(SyscallReturn::ok(new_fd as u64));
        }
        _ => ctx.set_return(SyscallReturn::invalid_op()),
    }
}
