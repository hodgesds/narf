#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_get_addr(ctx: &mut dyn TrapContext, peer: bool) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let len_ptr = args.arg2;
    // Linux __sys_getsockname/getpeername: sockfd_lookup_light gives
    // -EBADF / -ENOTSOCK, then the family op (-ENOTCONN for getpeername on an
    // unconnected socket).
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let op = if peer {
        crate::socket::SocketOp::GetPeerName
    } else {
        crate::socket::SocketOp::GetSockName
    };
    let result = sock.dispatch_op(op);
    match result {
        crate::socket::SocketOpResult::Addr(addr) => {
            // `move_addr_to_user`: -EFAULT for a NULL/faulting addrlen or
            // address buffer, -EINVAL for a negative *addrlen.
            match move_addr_to_user(Some(&addr), addr_ptr, len_ptr) {
                Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
                Err(errno) => ctx.set_return(errno_ret(errno)),
            }
        }
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(errno_ret(EINVAL)), // unreachable
    }
}
