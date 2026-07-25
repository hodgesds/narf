#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pidfd_open(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let user_pid = args.arg0;
    let _flags = args.arg1 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if user_pid == 0 {
        ctx.set_return(fail);
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
            ctx.set_return(fail);
            return;
        }
    };
    // Pid is alive if it has a registered PID→TaskId mapping. A
    // missing mapping means the pid was never minted or its task has
    // already torn down — treat as zombie (immediately readable).
    let alive = pid_to_task_raw(pid_raw).is_some();
    let state = crate::pidfd::mint_for(pid_raw, alive);
    let file: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
        alloc::sync::Arc::new(crate::pidfd::PidFdFile::new(state));
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: file,
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    }) {
        Some(n) => n,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}
