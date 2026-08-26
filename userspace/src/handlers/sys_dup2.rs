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
    // `ksys_dup3`: `if (newfd >= rlimit(RLIMIT_NOFILE)) return -EBADF;`, and
    // the -EMFILE that `expand_files` would raise for the same slot is
    // deliberately remapped to -EBADF too (`if (err == -EMFILE) goto Ebadf;`).
    // dup2/dup3 name an exact descriptor, so an out-of-range target is a bad
    // descriptor argument rather than exhaustion — unlike dup(2), which asks
    // for any free slot and does report -EMFILE.
    {
        let nofile = read_rlimit(task, RLIMIT_NOFILE_RESOURCE)
            .map(|limit| limit.cur)
            .unwrap_or_else(|| default_rlimits()[RLIMIT_NOFILE_RESOURCE].cur);
        if u64::from(newfd) >= nofile {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
    }
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
