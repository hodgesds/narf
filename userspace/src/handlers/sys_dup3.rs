#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_dup3(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let oldfd = args.arg0 as u32;
    let newfd = args.arg1 as u32;
    let flags = args.arg2 as u32;
    // fs/file.c::ksys_dup3 accepts exactly O_CLOEXEC. FD_CLOEXEC is the
    // per-slot bit used by fcntl, not a dup3 flag, despite sharing value 1.
    if flags & !crate::fd::O_CLOEXEC != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    // Linux dup3: differ from dup2 by failing on oldfd == newfd. The
    // call exists to atomically install FD_CLOEXEC, which only makes
    // sense when actually duplicating to a different slot.
    if oldfd == newfd {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    let task = current_task_id();
    let descriptor_flags = if flags & crate::fd::O_CLOEXEC != 0 {
        crate::fd::FD_CLOEXEC
    } else {
        0
    };
    let outcome = fd::with_table(task, |t| t.duplicate_to(oldfd, newfd, descriptor_flags));
    match outcome {
        Some(Some(())) => {
            #[cfg(feature = "linux-compat")]
            crate::mqueue::duplicate_fd_path(task, oldfd, newfd);
            ctx.set_return(SyscallReturn::ok(newfd as u64));
        }
        // oldfd not open → -EBADF (was InvalidOp).
        _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
    }
}
