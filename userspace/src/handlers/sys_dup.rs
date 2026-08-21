#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_dup(ctx: &mut dyn TrapContext) {
    let oldfd = ctx.args().arg0 as u32;
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(oldfd)?;
        // dup(2) shares the OPEN FILE DESCRIPTION (`fs/file.c::dup_fd` /
        // `fcntl.c`): the new fd refers to the same `struct file`, so file
        // offset and status flags (O_NONBLOCK/O_APPEND) are common to both.
        // LINUX-GAP: NARF has no shared description object — this SNAPSHOTS
        // offset + status_flags instead of aliasing them, so a later
        // lseek/F_SETFL on one fd is not seen by the other. Per-fd flags
        // (FD_CLOEXEC) start clear on the duplicate, matching Linux.
        let clone = crate::fd::FdEntry {
            ops: entry.ops.clone(),
            offset: entry.offset,
            flags: 0,
            status_flags: entry.status_flags,
        };
        Some(t.open(clone))
    });
    match outcome {
        Some(Some(new_fd)) => {
            #[cfg(feature = "linux-compat")]
            crate::mqueue::duplicate_fd_path(task, oldfd, new_fd);
            ctx.set_return(SyscallReturn::ok(new_fd as u64));
        }
        // oldfd is not an open file descriptor → EBADF.
        _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
    }
}
