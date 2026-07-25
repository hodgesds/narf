#[allow(unused_imports)]
use super::*;

/// `close_range(first, last, flags)` — close every open fd in the
/// inclusive range, or mark them FD_CLOEXEC with CLOSE_RANGE_CLOEXEC.
pub(crate) fn sys_close_range(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let first = a.arg0 as u32;
    let last = a.arg1 as u32;
    let flags = a.arg2 as u32;
    const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
    const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
    if first > last || flags & !(CLOSE_RANGE_CLOEXEC | CLOSE_RANGE_UNSHARE) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let cloexec = flags & CLOSE_RANGE_CLOEXEC != 0;
    let task = current_task_id();
    fd::with_table(task, |t| t.close_range(first, last, cloexec));
    ctx.set_return(SyscallReturn::ok(0));
}
