#[allow(unused_imports)]
use super::*;

/// `pidfd_getfd(pidfd, targetfd, flags)` — clone an fd out of the
/// process referenced by `pidfd` into the caller's fd table. Since an
/// `FdEntry` holds an `Arc<dyn FileOps>`, the clone shares the same open
/// file description, exactly like Linux.
pub(crate) fn sys_pidfd_getfd(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let pidfd = a.arg0 as u32;
    let targetfd = a.arg1 as u32;
    if a.arg2 != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let task = current_task_id();
    let target_pid = match fd::with_table(task, |t| {
        t.get(pidfd).and_then(|e| e.ops.pidfd_target_pid())
    })
    .flatten()
    {
        Some(p) => p,
        None => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF (not a pidfd)
            return;
        }
    };
    let target_tid = if target_pid == task {
        task
    } else {
        match pid_to_task_raw(target_pid) {
            Some(t) => t,
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    };
    let entry = fd::with_table(target_tid, |t| t.get(targetfd).cloned()).flatten();
    let entry = match entry {
        Some(e) => e,
        None => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        }
    };
    match fd::install(task, entry) {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        None => {
            // `kernel/pid.c::SYSCALL_DEFINE3(pidfd_getfd)` ends in
            // `get_unused_fd_flags`, so a full table is -EMFILE. -EBADF here
            // would blame the caller's descriptor arguments, which were fine.
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
        }
    }
}
