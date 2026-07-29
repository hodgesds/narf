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
    let sid_outer = read_sid(target_task);
    let sid_user = report_pid_to(current_task_id(), sid_outer);
    ctx.set_return(SyscallReturn::ok(sid_user));
}
