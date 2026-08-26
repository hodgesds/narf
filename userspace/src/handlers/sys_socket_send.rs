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
    // Linux `__sys_sendto()` imports the payload iterator before looking up the
    // descriptor.  NARF eagerly copies that iterator into a kernel Vec, so an
    // unreadable non-empty payload must likewise win over EBADF/ENOTSOCK.
    let buf = if buf_len > 0 {
        // SAFETY: AS active; SMAP bracket inside copy_from_user_vec.
        match unsafe { copy_from_user_vec(buf_ptr, buf_len) } {
            Ok(b) => b,
            Err(errno) => {
                ctx.set_return(SyscallReturn::ok((-(errno as i64)) as u64));
                return;
            }
        }
    } else {
        alloc::vec::Vec::new()
    };
    let sock = match current_socket_result(fd) {
        Ok(socket) => socket,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    // sendto's sockaddr import follows descriptor/socket validation.  Unlike
    // sendmsg, move_addr_to_kernel rejects (rather than clamps) a length above
    // sockaddr_storage, and a failed user copy is EFAULT rather than silently
    // turning the call into a connected send.
    let dest = match import_sendto_addr(addr_ptr, addr_len) {
        Ok(addr) => addr,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
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
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)),
    }
}

fn import_sendto_addr(ptr: u64, raw_len: u64) -> Result<Option<crate::socket::SockAddr>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    let len = raw_len as i32;
    if !(0..=128).contains(&len) {
        return Err(22); // EINVAL
    }
    if len == 0 {
        return Ok(None);
    }
    if len < 2 {
        return Err(22); // no complete sa_family_t
    }
    let mut bytes = alloc::vec![0u8; len as usize];
    // SAFETY: copy_from_user validates the complete address range and opens the
    // architecture user-access window.
    unsafe { copy_from_user(&mut bytes, ptr) }.map_err(|_| 14i64)?;
    Ok(Some(crate::socket::SockAddr {
        family: u16::from_ne_bytes([bytes[0], bytes[1]]),
        body: bytes[2..].to_vec(),
    }))
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
