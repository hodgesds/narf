#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pidfd_open(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid_raw = args.arg0;
    let _flags = args.arg1 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if pid_raw == 0 {
        ctx.set_return(fail);
        return;
    }
    // Pid is alive if it has a registered PID→TaskId mapping. A
    // missing mapping means the pid was never minted or its task has
    // already torn down — treat as zombie (immediately readable).
    let alive = pid_to_task_raw(pid_raw).is_some();
    let state = crate::pidfd::mint_for(pid_raw, alive);
    let file: alloc::sync::Arc<dyn narf_filesystem::FileOps> =
        alloc::sync::Arc::new(crate::pidfd::PidFdFile::new(state));
    let task = current_task_id();
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
