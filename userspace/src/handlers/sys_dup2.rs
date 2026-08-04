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
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(oldfd)?;
        // dup2(2) shares the open file description — offset + status flags
        // travel with the duplicate (see the LINUX-GAP note in sys_dup:
        // NARF snapshots rather than aliases them). Resetting them to zero
        // here was a real divergence: the X server's Popen child does
        // `dup2(pipefd, 0)` and the duplicate must keep the description's
        // flags.
        let clone = crate::fd::FdEntry {
            ops: entry.ops.clone(),
            offset: entry.offset,
            flags: 0,
            status_flags: entry.status_flags,
        };
        // Replace whatever sat at `newfd` (POSIX: silently close).
        t.set(newfd, clone);
        Some(())
    });
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
