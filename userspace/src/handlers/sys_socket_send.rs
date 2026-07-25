#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_send(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1;
    let buf_len = args.arg2 as usize;
    let flags = args.arg3 as u32;
    // arg4 / arg5: sendto's destination address (NULL/0 for
    // connected stream sockets, non-NULL for connectionless
    // datagram sends).
    let addr_ptr = args.arg4;
    let addr_len = args.arg5;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Copy user send buffer into kernel memory under the SMAP bracket.
    // Validate length before allocating — reject oversized len with EINVAL.
    let buf = if buf_len > 0 {
        // SAFETY: AS active; SMAP bracket inside copy_from_user_vec.
        match unsafe { copy_from_user_vec(buf_ptr, buf_len) } {
            Ok(b) => b,
            Err(_) => {
                ctx.set_return(fail);
                return;
            }
        }
    } else {
        alloc::vec::Vec::new()
    };
    let dest = if addr_ptr != 0 && addr_len >= 2 {
        copy_user_addr(addr_ptr, addr_len)
    } else {
        None
    };
    match sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: &buf,
        flags,
        addr: dest,
    }) {
        crate::socket::SocketOpResult::Ok(n) => ctx.set_return(SyscallReturn::ok(n)),
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            // Yield + retry from libc.
            ctx.set_return(SyscallReturn::ok(0));
        }
        // Surface the real errno (ECONNREFUSED for a datagram to a missing
        // name, ENOTCONN, EINVAL, …) rather than a bare -1/EPERM.
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        // Send never yields Accepted/Received/Addr; keep the match total.
        _ => ctx.set_return(fail),
    }
}
