#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_dup2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let oldfd = args.arg0 as u32;
    let newfd = args.arg1 as u32;
    if oldfd == newfd {
        // POSIX: dup2(fd, fd) is a no-op + returns fd as long as fd
        // is a valid open fd. Verify validity before short-circuiting.
        let task = current_task_id();
        let valid = fd::with_table(task, |t| t.get(oldfd).is_some()).unwrap_or(false);
        if valid {
            ctx.set_return(SyscallReturn::ok(newfd as u64));
        } else {
            // dup2 with an invalid oldfd → -EBADF (was InvalidOp).
            ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        }
        return;
    }
    let task = current_task_id();
    // Replacing the target slot installs another reference to oldfd's shared
    // open-file description; descriptor flags start clear.
    let outcome = fd::with_table(task, |t| t.duplicate_to(oldfd, newfd, 0));
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
