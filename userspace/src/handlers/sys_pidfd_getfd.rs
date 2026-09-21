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
        ctx.set_return(errno_ret(EINVAL));
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
            ctx.set_return(errno_ret(EBADF)); // EBADF (not a pidfd)
            return;
        }
    };
    let target_tid = if target_pid == task {
        task
    } else {
        match pid_to_task_raw(target_pid) {
            Some(t) => t,
            None => {
                ctx.set_return(errno_ret(ESRCH));
                return;
            }
        }
    };
    if !ptrace_may_access(task, target_tid) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    let entry = fd::with_table(target_tid, |t| t.get(targetfd).cloned()).flatten();
    let mut entry = match entry {
        Some(e) => e,
        None => {
            ctx.set_return(errno_ret(EBADF));
            return;
        }
    };
    // Linux `receive_fd(file, NULL, O_CLOEXEC)`: the descriptor in the
    // calling process is always allocated with close-on-exec set.
    entry.flags |= crate::fd::FD_CLOEXEC;
    match fd::install(task, entry) {
        Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        None => {
            // `kernel/pid.c::SYSCALL_DEFINE3(pidfd_getfd)` ends in
            // `get_unused_fd_flags`, so a full table is -EMFILE. -EBADF here
            // would blame the caller's descriptor arguments, which were fine.
            ctx.set_return(errno_ret(EMFILE));
        }
    }
}
