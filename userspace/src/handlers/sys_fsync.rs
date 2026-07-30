#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fsync(ctx: &mut dyn TrapContext) {
    sync_fd(ctx, false);
}

pub(crate) fn sys_fdatasync(ctx: &mut dyn TrapContext) {
    sync_fd(ctx, true);
}

fn sync_fd(ctx: &mut dyn TrapContext, data_only: bool) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let ops = fd::with_table(task, |t| t.get(fd).map(|entry| entry.ops.clone())).flatten();
    let Some(ops) = ops else {
        // fd isn't open → -EBADF (was the -1 sentinel musl maps to EPERM).
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    };
    // A generic filesystem may not expose physical page-cache frames for a
    // MAP_SHARED mapping. NARF then maps private frames and records them for
    // writeback; commit those bytes before the filesystem's own fsync so
    // fsync retains its Linux data-before-metadata ordering.
    if crate::mapped_file::flush_current_file(&ops).is_err() {
        ctx.set_return(SyscallReturn::ok((-5i64) as u64)); // -EIO
        return;
    }
    match poll_blocking(ops.fsync(data_only)) {
        Some(Ok(())) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(SyscallReturn::ok((-5i64) as u64)), // -EIO
    }
}
