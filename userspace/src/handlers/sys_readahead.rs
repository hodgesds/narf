#[allow(unused_imports)]
use super::*;

/// `readahead(fd, offset, count)` — page-cache populate hint. NARF's
/// in-memory FSes need no readahead; accept for a valid fd, EBADF
/// otherwise.
pub(crate) fn sys_readahead(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let valid = fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false);
    if valid {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
    }
}
