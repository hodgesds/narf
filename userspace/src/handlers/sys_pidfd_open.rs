#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pidfd_open(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let user_pid = args.arg0;
    let flags = args.arg1 as u32;
    // `kernel/pid.c::SYSCALL_DEFINE2(pidfd_open)`:
    //
    //     if (flags & ~(PIDFD_NONBLOCK | PIDFD_THREAD)) return -EINVAL;
    //     if (pid <= 0)                                 return -EINVAL;
    //
    // PIDFD_NONBLOCK == O_NONBLOCK, PIDFD_THREAD == O_EXCL
    // (include/uapi/linux/pidfd.h). Any other bit is a malformed argument and
    // gets -EINVAL — distinct from the -ESRCH a valid-but-absent pid gets and
    // the -EMFILE an exhausted table gets.
    const PIDFD_NONBLOCK: u32 = 0o4000; // O_NONBLOCK
    const PIDFD_THREAD: u32 = 0o200; // O_EXCL
    if flags & !(PIDFD_NONBLOCK | PIDFD_THREAD) != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // pid_t is 32-bit signed; the malformed case is `pid <= 0`, not just
    // `== 0` — a NEGATIVE pid must also be -EINVAL, never fall through to the
    // -ESRCH below (which is reserved for a well-formed pid that names no
    // process). Truncate to i32 so the register's upper bits can't hide the
    // sign.
    if (user_pid as i32) <= 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // `pidfd_open(2)` accepts a PID in the caller's namespace. Keep the
    // pidfd itself keyed by the outer id, like pidfd exit notification
    // and signal delivery. Without this translation, systemd's executor in a
    // PID namespace opened inner PID 4 as outer PID 4, SIGKILLed an unrelated
    // stale process, then blocked forever in waitid(P_PIDFD) for its real
    // sandbox helper.
    //
    // `p = find_get_pid(pid); if (!p) return -ESRCH;` (kernel/pid.c:699),
    // then `pidfd_prepare` (kernel/fork.c:1883-1891):
    //
    //     if (!pid_has_task(pid, PIDTYPE_PID))                 return -ESRCH;
    //     if (!(flags & PIDFD_THREAD) && !pid_has_task(pid, PIDTYPE_TGID))
    //                                                          return -ENOENT;
    //
    // A zombie keeps its pid binding until it is reaped, so "no task" here is
    // a pid that was never used or has been reaped: -ESRCH, never a pidfd
    // that reads as already exited. A non-leader thread's tid names a task
    // but no thread group: -ENOENT unless the caller asked for PIDFD_THREAD.
    let task = current_task_id();
    let Some(target) = find_task_by_vpid(task, user_pid as i32) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    let is_leader = process_state_key(target) == target;
    if !is_leader && flags & PIDFD_THREAD == 0 {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    // The outer id the pidfd is keyed by: the process id for a leader, the
    // thread's own tid for a PIDFD_THREAD pidfd on a non-leader.
    let pid_raw = if is_leader {
        task_to_pid_raw(target).unwrap_or(target)
    } else {
        task_to_linux_tid_raw(target).unwrap_or(target)
    };
    let state = crate::pidfd::mint_for(pid_raw, target, true);
    let file: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
        alloc::sync::Arc::new(crate::pidfd::PidFdFile::new(state));
    let new_fd = match fd::install(task, crate::fd::FdEntry {
            ops: file,
            offset: 0,
            // Linux `pidfd_create` opens the descriptor O_RDWR | O_CLOEXEC, so
            // the pidfd is close-on-exec; PIDFD_NONBLOCK maps to O_NONBLOCK on
            // the description (visible via `fcntl(F_GETFL)`).
            flags: crate::fd::FD_CLOEXEC,
            status_flags: if flags & PIDFD_NONBLOCK != 0 {
                PIDFD_NONBLOCK
            } else {
                0
            },
        }) {
        Some(n) => n,
        None => {
            // The descriptor comes from `get_unused_fd_flags`, so a table at
            // RLIMIT_NOFILE is -EMFILE.
            ctx.set_return(errno_ret(EMFILE));
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}
