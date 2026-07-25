#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sock_register_buf(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    let len = args.arg1;
    let task = current_task_id();
    match crate::socket::register_user_buffer(task, ptr, len) {
        Some(id) => ctx.set_return(SyscallReturn::ok(id as u64)),
        None => ctx.set_return(SyscallReturn::ok((-1i64) as u64)),
    }
}
