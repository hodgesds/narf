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
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let cloexec = flags & CLOSE_RANGE_CLOEXEC != 0;
    let task = current_task_id();
    // Linux's close_range() detaches a shared `files_struct` before it
    // applies either operation.  In particular, a CLONE_FILES sandbox helper
    // uses CLOSE_RANGE_UNSHARE while discarding inherited fds; closing the
    // shared table would silently invalidate its siblings' descriptors.
    //
    // `fd::unshare_table` snapshots the table only when another task holds
    // the same Arc.  It deliberately happens before both close and CLOEXEC:
    // the latter still needs every descriptor copied so it remains usable by
    // the caller until a subsequent exec.
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        crate::fd::unshare_table(task);
    }
    if let Some(closed) = fd::with_table(task, |t| t.close_range(first, last, cloexec)) {
        fd::release_closed(task, closed);
    }
    ctx.set_return(SyscallReturn::ok(0));
}
