#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getsid(ctx: &mut dyn TrapContext) {
    let pid = ctx.args().arg0;
    let target_task = if pid == 0 {
        current_task_id()
    } else {
        match accept_pid_from(current_task_id(), pid) {
            Some(outer) => proc_pid_to_tid(outer),
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    };
    // `read_sid` returns the session id in TaskId space (setsid stores
    // SID_TABLE[tid] = tid). Translate TaskId -> visible ProcessId the same
    // way getpgid/getpgrp do, via `pgid_to_user`. The previous
    // `report_pid_to(read_sid(..))` skipped the TaskId->pid hop: identity in a
    // non-container build (so it leaked a raw TaskId) and, in a container,
    // fed report_pid_to a TaskId where it expects an outer pid. agetty/login
    // compare getsid(0) against tcgetsid(fd) (which uses the correct
    // `current_task_sid_user` -> `pgid_to_user` path); the two must live in
    // the same number space or the session-ownership check passes only by
    // coincidence.
    let sid_user = pgid_to_user(read_sid(target_task));
    ctx.set_return(SyscallReturn::ok(sid_user));
}
