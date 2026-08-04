#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_dup3(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let oldfd = args.arg0 as u32;
    let newfd = args.arg1 as u32;
    let flags = args.arg2 as u32;
    // Linux dup3: differ from dup2 by failing on oldfd == newfd. The
    // call exists to atomically install FD_CLOEXEC, which only makes
    // sense when actually duplicating to a different slot.
    if oldfd == newfd {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(oldfd)?;
        // dup3(2) shares the open file description — offset + status flags
        // travel with the duplicate (LINUX-GAP: snapshotted, not aliased;
        // see sys_dup).
        let clone = crate::fd::FdEntry {
            ops: entry.ops.clone(),
            offset: entry.offset,
            // Set FD_CLOEXEC when the caller passes O_CLOEXEC (stock
            // glibc/musl, bit 0x80000) OR the bare FD_CLOEXEC bit
            // (narf-libc). Either way the slot bit is FD_CLOEXEC.
            flags: if flags & (crate::fd::O_CLOEXEC | crate::fd::FD_CLOEXEC) != 0 {
                crate::fd::FD_CLOEXEC
            } else {
                0
            },
            status_flags: entry.status_flags,
        };
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
