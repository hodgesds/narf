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
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    // pid_t is 32-bit signed; the malformed case is `pid <= 0`, not just
    // `== 0` — a NEGATIVE pid must also be -EINVAL, never fall through to the
    // -ESRCH below (which is reserved for a well-formed pid that names no
    // process). Truncate to i32 so the register's upper bits can't hide the
    // sign.
    if (user_pid as i32) <= 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    // `pidfd_open(2)` accepts a PID in the caller's namespace. Keep the
    // pidfd itself keyed by the outer ProcessId, like pidfd exit notification
    // and signal delivery. Without this translation, systemd's executor in a
    // PID namespace opened inner PID 4 as outer PID 4, SIGKILLed an unrelated
    // stale process, then blocked forever in waitid(P_PIDFD) for its real
    // sandbox helper.
    let task = current_task_id();
    let pid_raw = match accept_pid_from(task, user_pid) {
        Some(pid) => pid,
        None => {
            // `pid = find_get_pid(pid); if (!pid) return -ESRCH;` — the pid is
            // well-formed but names no process, which is a different answer
            // from the -EINVAL above and the -EMFILE below.
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // -ESRCH
            return;
        }
    };
    // Pid is alive if it has a registered PID→TaskId mapping. A
    // missing mapping means the pid was never minted or its task has
    // already torn down — treat as zombie (immediately readable). The
    // resolved TaskId (if any) is the authoritative, reuse-safe exit signal
    // for `poll_readiness`.
    let target_tid = pid_to_task_raw(pid_raw);
    let alive = target_tid.is_some();
    let state = crate::pidfd::mint_for(pid_raw, target_tid.unwrap_or(0), alive);
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
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}
