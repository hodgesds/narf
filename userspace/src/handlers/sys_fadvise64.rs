#[allow(unused_imports)]
use super::*;

/// `fadvise64(fd, offset, len, advice)` — access-pattern hint. NARF's
/// in-memory FSes ignore it; accept for a valid fd, EBADF otherwise.
pub(crate) fn sys_fadvise64(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let valid = fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false);
    if valid {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
    }
}
