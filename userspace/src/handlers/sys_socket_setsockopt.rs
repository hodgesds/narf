#[allow(unused_imports)]
use super::*;

/// `setsockopt(fd, level, optname, opt_val, opt_len)`.
/// Linux ref: net/socket.c:SYSCALL_DEFINE5(setsockopt, ...).
pub(crate) fn sys_socket_setsockopt(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let level = args.arg1 as u32;
    let name = args.arg2 as u32;
    let val_ptr = args.arg3;
    let val_len = args.arg4 as usize;
    // Linux __sys_setsockopt: sockfd_lookup_light → -EBADF / -ENOTSOCK, then
    // do_sock_setsockopt `optlen < 0 → -EINVAL` (a negative optlen from
    // userspace reads as a huge usize here — caught by the > 256 cap), then the
    // option handler's `optlen < sizeof(int) → -EINVAL` (so optlen==0 is
    // -EINVAL) and finally its copy_from_user of optval → -EFAULT.
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    if val_len == 0 || val_len > 256 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let mut buf = alloc::vec![0u8; val_len];
    // SAFETY: AS active; SMAP bracket inside copy_from_user. A NULL/faulting
    // optval is caught here → -EFAULT.
    if unsafe { copy_from_user(&mut buf, val_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    match sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level,
        name,
        value: &buf,
    }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        // -ENOPROTOOPT (unknown option), -EINVAL, -EPERM, … from the handler.
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // -EINVAL (unreachable)
    }
}
