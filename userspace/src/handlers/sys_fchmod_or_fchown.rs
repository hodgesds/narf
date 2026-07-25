#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fchmod_or_fchown(ctx: &mut dyn TrapContext) {
    let fd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let known = fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false);
    if known {
        // inotify: fchmod/fchown is IN_ATTRIB on the fd's file, if watched.
        #[cfg(feature = "linux-compat")]
        crate::mqueue::notify_attrib_fd(task, fd);
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        // fd isn't open → -EBADF (was the -1 sentinel musl maps to EPERM).
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
    }
}
