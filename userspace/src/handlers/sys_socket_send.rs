#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_send(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1;
    // `import_ubuf` clamps an oversized length to MAX_RW_COUNT rather than
    // failing it. A stream send then transfers a prefix; every datagram
    // protocol's own size limit (UDP 65507, AF_UNIX sndbuf) is far below the
    // NARF bound and still reports -EMSGSIZE for the clamped length.
    let buf_len = core::cmp::min(args.arg2 as usize, MAX_USER_COPY);
    let flags = args.arg3 as u32;
    // arg4 / arg5: sendto's destination address (NULL/0 for
    // connected stream sockets, non-NULL for connectionless
    // datagram sends).
    let addr_ptr = args.arg4;
    let addr_len = args.arg5;
    // A blocking TCP or AF_UNIX stream send queues the WHOLE buffer before
    // returning: its protocol send loop sleeps for space and this
    // progress-keeping path never copies more of a multi-megabyte user buffer
    // than it is about to queue.
    const MSG_DONTWAIT: u32 = 0x40;
    const PLAIN_FLAGS: u32 = crate::socket::MSG_NOSIGNAL | 0x8000; // MSG_MORE
    if addr_ptr == 0
        && buf_len > 0
        && flags & !PLAIN_FLAGS == 0
        && validate_user_range(buf_ptr, buf_len).is_ok()
    {
        if let Ok(sock) = current_socket_result(fd) {
            if flags & MSG_DONTWAIT == 0
                && !socket_listener_nonblock(current_task_id(), fd, sock.as_ref())
            {
                let resumed = handler_sys_socket_recv::sock_timeo_take(ctx, &sock);
                if sock.domain == crate::socket::AF_UNIX
                    && sock.kind == crate::socket::SOCK_STREAM
                {
                    unix_blocking_send(ctx, fd, flags, &sock, buf_ptr, buf_len, resumed);
                    return;
                }
                if let Some(tcb) = sock.kernel_tcb_id() {
                    tcp_blocking_send(ctx, fd, flags, &sock, tcb, buf_ptr, buf_len, resumed);
                    return;
                }
            }
        }
    }
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
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // SO_SNDTIMEO: pick up this call's deadline if it is re-executing.
    let resumed = handler_sys_socket_recv::sock_timeo_take(ctx, &sock);
    // sendto's sockaddr import follows descriptor/socket validation.  Unlike
    // sendmsg, move_addr_to_kernel rejects (rather than clamps) a length above
    // sockaddr_storage, and a failed user copy is EFAULT rather than silently
    // turning the call into a connected send.
    let dest = match import_sendto_addr(addr_ptr, addr_len) {
        Ok(addr) => addr,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
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
            socket_send_would_block(ctx, fd, flags, sock.as_ref(), resumed);
        }
        crate::socket::SocketOpResult::Err(e) => {
            // A broken-pipe send raises SIGPIPE to the sender unless MSG_NOSIGNAL
            // is set, matching Linux sk_stream_error (net/core/stream.c:194) and
            // unix_stream_sendmsg (net/unix/af_unix.c:2500). SIGPIPE's default
            // action is Terminate, so a client that neither sets MSG_NOSIGNAL nor
            // ignores SIGPIPE dies here exactly as on Linux.
            // Datagram/seqpacket sockets never signal: their EPIPE comes from
            // `sock_alloc_send_pskb` (net/core/sock.c:2873), and only the
            // stream error paths raise SIGPIPE (net/core/stream.c:191).
            if e == crate::socket::SockError::Pipe
                && flags & crate::socket::MSG_NOSIGNAL == 0
                && sock.epipe_raises_sigpipe()
            {
                raise_signal_pending(current_task_id(), 13); // SIGPIPE
            }
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        // Send never yields Accepted/Received/Addr; keep the match total.
        _ => ctx.set_return(errno_ret(EINVAL)),
    }
}

/// The blocking kernel-TCP send of `send`/`sendto`/`write`: see
/// `tcp_send_all`. Errors before any byte was queued follow the ordinary
/// send rules (EPIPE raises SIGPIPE unless MSG_NOSIGNAL).
#[allow(clippy::too_many_arguments)]
pub(super) fn tcp_blocking_send(
    ctx: &mut dyn TrapContext,
    fd: u32,
    flags: u32,
    sock: &crate::socket::SocketFile,
    tcb: u32,
    buf_ptr: u64,
    buf_len: usize,
    resumed: Option<u64>,
) {
    use handler_sys_socket_recv::SendAll;
    match handler_sys_socket_recv::tcp_send_all(ctx, sock, tcb, buf_ptr, buf_len, resumed) {
        SendAll::Done(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        SendAll::Parked => {}
        SendAll::WouldBlock => socket_send_would_block(ctx, fd, flags, sock, resumed),
        SendAll::Err(e) => {
            if e == crate::socket::SockError::Pipe
                && flags & crate::socket::MSG_NOSIGNAL == 0
                && sock.epipe_raises_sigpipe()
            {
                raise_signal_pending(current_task_id(), 13); // SIGPIPE
            }
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
    }
}

/// The AF_UNIX counterpart of [`tcp_blocking_send`].  A Unix stream's ring
/// deliberately accepts only the units that fit its current send buffer; for
/// a blocking syscall, Linux waits and queues the rest.  Keep the user-buffer
/// offset in the per-task stream-progress cell while the task is parked so a
/// re-execution never repeats a prefix (or a control boundary attached to it).
#[allow(clippy::too_many_arguments)]
pub(super) fn unix_blocking_send(
    ctx: &mut dyn TrapContext,
    fd: u32,
    flags: u32,
    sock: &crate::socket::SocketFile,
    buf_ptr: u64,
    buf_len: usize,
    resumed: Option<u64>,
) {
    use handler_sys_socket_recv::SendAll;
    match unix_send_all(ctx, sock, buf_ptr, buf_len, resumed) {
        SendAll::Done(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
        SendAll::Parked => {}
        SendAll::WouldBlock => socket_send_would_block(ctx, fd, flags, sock, resumed),
        SendAll::Err(e) => {
            if e == crate::socket::SockError::Pipe
                && flags & crate::socket::MSG_NOSIGNAL == 0
                && sock.epipe_raises_sigpipe()
            {
                raise_signal_pending(current_task_id(), 13); // SIGPIPE
            }
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
    }
}

/// Queue a blocking AF_UNIX stream write without eagerly copying the complete
/// user buffer.  `RingBuf::write_stream_with_fds` may return a short count
/// when its send-buffer charge reaches the configured limit; that is progress,
/// not the result of the blocking syscall.  Match `unix_stream_sendmsg` by
/// waiting for POLL_OUT and retaining the completed prefix across restarts.
fn unix_send_all(
    ctx: &mut dyn TrapContext,
    sock: &crate::socket::SocketFile,
    user_ptr: u64,
    len: usize,
    resumed_timeo: Option<u64>,
) -> handler_sys_socket_recv::SendAll {
    use handler_sys_socket_recv::{SendAll, StreamWait};

    const CHUNK: usize = 1 << 20;
    let mut done = handler_sys_socket_recv::sock_progress_take(ctx, sock).min(len);
    while done < len {
        let want = core::cmp::min(CHUNK, len - done);
        // SAFETY: the caller validated the complete range.  This bounded copy
        // still handles an unmap race; after committed progress Linux returns
        // that prefix rather than replacing it with EFAULT.
        let payload = match unsafe { copy_from_user_vec(user_ptr + done as u64, want) } {
            Ok(payload) => payload,
            Err(_) if done > 0 => return SendAll::Done(done),
            Err(errno) => return SendAll::Err(crate::socket::SockError::Stack(errno as i32)),
        };
        match sock.unix_sendmsg(&payload, alloc::vec::Vec::new(), None) {
            Ok(n) => {
                if n != 0 {
                    done += n;
                    continue;
                }
            }
            Err(crate::socket::SockError::WouldBlock) => {}
            Err(_) if done > 0 => return SendAll::Done(done),
            Err(error) => return SendAll::Err(error),
        }
        if done == 0 {
            return SendAll::WouldBlock;
        }
        match handler_sys_socket_recv::stream_wait_with_progress(
            ctx,
            sock,
            narf_filesystem::POLL_OUT | narf_filesystem::POLL_HUP,
            sock.sndtimeo(),
            resumed_timeo,
            done,
        ) {
            StreamWait::Parked => return SendAll::Parked,
            StreamWait::Return => return SendAll::Done(done),
        }
    }
    SendAll::Done(done)
}

fn import_sendto_addr(ptr: u64, raw_len: u64) -> Result<Option<crate::socket::SockAddr>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    let len = raw_len as i32;
    if !(0..=128).contains(&len) {
        return Err(EINVAL);
    }
    if len == 0 {
        // A non-NULL address is still present when `addrlen == 0`.
        // `move_addr_to_kernel` imports an empty sockaddr and UDP rejects its
        // short length with EINVAL; it must not become a connected send.
        return Ok(Some(crate::socket::SockAddr {
            family: crate::socket::AF_UNSPEC,
            body: alloc::vec::Vec::new(),
        }));
    }
    let mut bytes = alloc::vec![0u8; len as usize];
    // SAFETY: copy_from_user validates the complete address range and opens the
    // architecture user-access window.
    unsafe { copy_from_user(&mut bytes, ptr) }.map_err(|_| EFAULT)?;
    if len < 2 {
        return Err(EINVAL); // no complete sa_family_t
    }
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
    resumed: Option<u64>,
) {
    const MSG_DONTWAIT: u32 = 0x40;
    let task = current_task_id();
    if flags & MSG_DONTWAIT != 0 || socket_listener_nonblock(task, fd, sock) {
        ctx.set_return(errno_ret(EAGAIN));
        return;
    }
    // Bounded by SO_SNDTIMEO (`sock_sndtimeo`). A kernel-test/non-stackful
    // context cannot sleep and gets the retryable EAGAIN, never a fabricated
    // zero-byte successful send.
    handler_sys_socket_recv::socket_block(
        ctx,
        sock,
        narf_filesystem::POLL_OUT | narf_filesystem::POLL_HUP,
        sock.sndtimeo(),
        resumed,
    );
}
