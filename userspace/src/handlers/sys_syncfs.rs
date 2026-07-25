#[allow(unused_imports)]
use super::*;

/// `syncfs(fd)` — flush the filesystem backing `fd`.
pub(crate) fn sys_syncfs(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let ops = fd::with_table(task, |t| t.get(fd).map(|entry| entry.ops.clone())).flatten();
    let Some(ops) = ops else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    match poll_blocking(ops.syncfs()) {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
    }
}
