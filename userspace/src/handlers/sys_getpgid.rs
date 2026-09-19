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

    let target = {
        if pid < 0 {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        }
        let caller = current_task_id();
        let Some(outer) = accept_pid_from(caller, pid as u64) else {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        };
        let Some(target) = pid_to_task_raw(outer) else {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        };
        // PID bindings survive while a task is a waitable zombie, exactly as
        // Linux's find_task_by_vpid does. Once reaped, both the binding and
        // registry entry disappear; reject either kind of stale/missing PID.
        if crate::task::task_get(target).is_none() {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        }
        target
    };
    ctx.set_return(SyscallReturn::ok(pgid_to_user(read_pgid(target))));
}
