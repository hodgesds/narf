#[allow(unused_imports)]
use super::*;

/// Upper bound on the optval bytes copied in for one setsockopt.
const SETSOCKOPT_MAX_COPY: usize = 4096;

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
    // do_sock_setsockopt `optlen < 0 → -EINVAL`, then the option handler's own
    // length check (`optlen < sizeof(int) → -EINVAL` for int options; a zero
    // optlen is legal for SO_BINDTODEVICE, where it unbinds) and finally its
    // copy_from_user of optval → -EFAULT.
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if (val_len as i32) < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // No NARF-modelled option is larger than a page. Linux copies at most the
    // option's own size from optval, so clamp rather than reject a longer
    // buffer (IP_MSFILTER / MCAST_MSFILTER carry variable-length tails).
    let val_len = core::cmp::min(val_len as u32 as usize, SETSOCKOPT_MAX_COPY);
    let mut buf = alloc::vec![0u8; val_len];
    // SAFETY: AS active; SMAP bracket inside copy_from_user. A NULL/faulting
    // optval is caught here → -EFAULT.
    if val_len != 0 && unsafe { copy_from_user(&mut buf, val_ptr) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
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
        _ => ctx.set_return(errno_ret(EINVAL)), // unreachable
    }
}
