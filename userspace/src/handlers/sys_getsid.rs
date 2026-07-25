#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getsid(ctx: &mut dyn TrapContext) {
    let pid = ctx.args().arg0;
    let target = if pid == 0 { current_task_id() } else { pid };
    ctx.set_return(SyscallReturn::ok(read_sid(target)));
}
