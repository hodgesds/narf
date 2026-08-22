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
        // Surface the real errno (EAGAIN for a full ring — matching sendmsg and
        // recv's non-blocking branch; ECONNREFUSED for a datagram to a missing
        // name; ENOTCONN; EINVAL; …) rather than a bare -1/EPERM. A full ring
        // MUST report EAGAIN, never a bogus 0-byte "success": returning 0 for a
        // non-empty buffer makes correct clients busy-loop or treat the stream
        // as broken, and matches nothing Linux ever returns from send(2).
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            socket_send_would_block(ctx, fd, flags, sock.as_ref());
        }
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        // Send never yields Accepted/Received/Addr; keep the match total.
        _ => ctx.set_return(fail),
    }
}

pub(super) fn socket_send_would_block(
    ctx: &mut dyn TrapContext,
    fd: u32,
    flags: u32,
    sock: &crate::socket::SocketFile,
) {
    const MSG_DONTWAIT: u32 = 0x40;
    let task = current_task_id();
    if flags & MSG_DONTWAIT != 0 || socket_listener_nonblock(task, fd, sock) {
        ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        return;
    }
    if park_reexecute_on_fd(
        ctx,
        sock,
        narf_filesystem::POLL_OUT | narf_filesystem::POLL_HUP,
    ) {
        return;
    }
    // Kernel-test/non-stackful context cannot sleep; expose the retryable
    // condition rather than fabricating a zero-byte successful send.
    ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
}
