#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sock_register_buf(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    let len = args.arg1;
    let task = current_task_id();
    // Argument validation before the bare -1 (which reached libc as EPERM — a
    // permission verdict about a caller whose only mistake was a bad argument).
    // Modelled on io_uring IORING_REGISTER_BUFFERS (io_uring/rsrc.c
    // io_buffer_validate): a NULL buffer base is -EFAULT (its access_ok check),
    // a zero-length entry is -EINVAL.
    if ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    match crate::socket::register_user_buffer(task, ptr, len) {
        Some(id) => ctx.set_return(SyscallReturn::ok(id as u64)),
        // register_user_buffer only rejects ptr==0/len==0, both handled above,
        // so a None here is an unexpected internal failure → -EINVAL.
        None => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // -EINVAL
    }
}
