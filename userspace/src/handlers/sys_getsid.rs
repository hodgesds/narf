#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getsid(ctx: &mut dyn TrapContext) {
    // `kernel/sys.c:1229` getsid: `pid_t pid`; 0 is `task_session(current)`,
    // anything else is `find_task_by_vpid(pid)` (:1240) — any thread, a
    // non-leader's tid included — or -ESRCH. The session lives in the
    // thread group's shared state, keyed by the group leader here.
    let pid = ctx.args().arg0 as i32;
    let caller = current_task_id();
    let target_task = if pid == 0 {
        caller
    } else {
        match find_task_by_vpid(caller, pid) {
            Some(task) => task,
            None => {
                ctx.set_return(errno_ret(ESRCH));
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
    let sid_user = pgid_to_user(read_sid(process_state_key(target_task)));
    ctx.set_return(SyscallReturn::ok(sid_user));
}
