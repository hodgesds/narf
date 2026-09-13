#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sock_register_buf(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    let len = args.arg1;
    let task = current_task_id();
    // Argument validation before the bare -1 (which reached libc as EPERM — a
    // permission verdict about a caller whose only mistake was a bad argument).
    // Modelled on io_uring IORING_REGISTER_BUFFERS (io_uring/rsrc.c): a NULL
    // buffer base with a non-zero length is -EFAULT (io_sqe_buffer_register:
    // `if (!iov->iov_base) { if (iov->iov_len) return -EFAULT; ... }`), and a
    // zero length is ALSO -EFAULT (io_validate_user_buf_range: `if (ulen >
    // SZ_1G || !ulen) return -EFAULT`). NARF does not implement sparse (NULL +
    // len 0) registrations, so both bad-base and zero-len reject with -EFAULT.
    if ptr == 0 || len == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    match crate::socket::register_user_buffer(task, ptr, len) {
        Some(id) => ctx.set_return(SyscallReturn::ok(id as u64)),
        // register_user_buffer only rejects ptr==0/len==0, both handled above,
        // so a None here would be an unexpected internal failure → -EFAULT
        // (same buffer-validation class).
        None => ctx.set_return(SyscallReturn::ok((-14i64) as u64)), // -EFAULT
    }
}
