#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getpgid(ctx: &mut dyn TrapContext) {
    // Linux receives a signed 32-bit pid_t. Negative values name no task for
    // getpgid and therefore fall through find_task_by_vpid to -ESRCH.
    let pid = ctx.args().arg0 as i32;
    // arg0 is a *visible* pid (0 = self); the table is task-id-keyed.
    if pid == 0 {
        ctx.set_return(SyscallReturn::ok(current_task_pgid_user()));
        return;
    }

    // `kernel/sys.c:1198` do_getpgid: `find_task_by_vpid(pid)` finds ANY
    // thread — a non-leader's tid included — and reports its process group
    // (shared thread-group state, keyed by the group leader here). It finds
    // waitable zombies too: their bindings survive until reap. Negative values
    // name no task.
    let Some(target) = find_task_by_vpid(current_task_id(), pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    ctx.set_return(SyscallReturn::ok(pgid_to_user(read_pgid(process_state_key(target)))));
}
