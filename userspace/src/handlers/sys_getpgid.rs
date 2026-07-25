#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getpgid(ctx: &mut dyn TrapContext) {
    let pid = ctx.args().arg0;
    // arg0 is a *visible* pid (0 = self); the table is task-id-keyed.
    let target = if pid == 0 {
        current_task_id()
    } else {
        pgid_from_user(pid)
    };
    ctx.set_return(SyscallReturn::ok(pgid_to_user(read_pgid(target))));
}
