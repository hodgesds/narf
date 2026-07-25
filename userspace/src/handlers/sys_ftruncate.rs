#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_ftruncate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let len = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        Some(poll_blocking(entry.ops.truncate(len)))
    });
    match outcome {
        Some(Some(Some(Ok(())))) => {
            // inotify: truncate changes file content → IN_MODIFY.
            #[cfg(feature = "linux-compat")]
            crate::mqueue::notify_modify_fd(task, fd);
            ctx.set_return(SyscallReturn::ok(0))
        }
        _ => ctx.set_return(fail),
    }
}
