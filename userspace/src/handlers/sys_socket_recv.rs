#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_recv(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1;
    // `import_ubuf` clamps an oversized length to MAX_RW_COUNT rather than
    // failing; NARF's staging bound is MAX_USER_COPY.
    let buf_len = core::cmp::min(args.arg2 as usize, MAX_USER_COPY);
    let flags = args.arg3 as u32;
    // Linux __sys_recvfrom: sockfd_lookup_light gives -EBADF / -ENOTSOCK; a
    // faulting destination buffer is -EFAULT; the family recv op surfaces
    // -EAGAIN / -ENOTCONN / -ECONNREFUSED / …
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // Validate destination range before issuing the Recv op.
    if buf_len > 0 && validate_user_range(buf_ptr, buf_len).is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    // A recv is non-blocking if the fd is O_NONBLOCK or the call carries
    // MSG_DONTWAIT (0x40). Such a recv must return EAGAIN the instant the ring
    // is empty-but-open — NEVER park. GLib's GSocket does exactly non-blocking
    // recv() + its own poll loop; parking here stalls its dbus auth handshake,
    // and the old "set 0 then yield" path could even surface a spurious 0 (EOF).
    const MSG_DONTWAIT: u32 = 0x40;
    // MSG_ERRQUEUE never waits either: `ip_recv_error` returns EAGAIN at once
    // when the error queue is empty (net/ipv4/ip_sockglue.c:535).
    let nonblock = (flags & (MSG_DONTWAIT | crate::socket::MSG_ERRQUEUE)) != 0
        || fd::with_table(current_task_id(), |t| {
            t.status_flags(fd)
                .map(|flags| flags & crate::fd::O_NONBLOCK != 0)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let mut buf = alloc::vec![0u8; buf_len];
    let result = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags,
    });
    let (result, truncated_full_len) = match result {
        crate::socket::SocketOpResult::ReceivedTruncated {
            copied,
            full_len,
            peer,
        } => (
            crate::socket::SocketOpResult::Received { n: copied, peer },
            Some(full_len),
        ),
        other => (other, None),
    };
    match result {
        crate::socket::SocketOpResult::Received { n, peer } => {
            // recv()/recvfrom() cannot return ancillary data. Consume and
            // drop any rights/credentials attached to this record so a later
            // recvmsg cannot steal them from the wrong message.
            drop(sock.unix_take_recv_fds());
            let _ = sock.recvmsg_cred();
            // Copy received bytes back to user under SMAP bracket.
            // SAFETY: ptr validated above; AS still active.
            // Linux permits recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC) as a
            // datagram-length probe. Do not validate/copy a zero-byte range:
            // a null pointer is valid when no payload bytes are requested.
            if n > 0 && unsafe { copy_to_user(buf_ptr, &buf[..n]) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
            // recvfrom source-address output: arg4 points to sockaddr storage,
            // arg5 points to its in/out socklen_t. Plain recv passes arg4 = 0.
            // `__sys_recvfrom` runs `move_addr_to_user` whenever `addr` is
            // non-NULL, so a NULL/faulting addrlen is -EFAULT and a
            // connection-oriented socket (no source address) reports 0.
            if args.arg4 != 0 {
                if let Err(errno) = move_addr_to_user(peer.as_ref(), args.arg4, args.arg5) {
                    ctx.set_return(errno_ret(errno));
                    return;
                }
            }
            let returned = if flags & crate::socket::MSG_TRUNC != 0 {
                truncated_full_len.unwrap_or(n)
            } else {
                n
            };
            ctx.set_return(SyscallReturn::ok(returned as u64));
        }
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            socket_recv_would_block(ctx, nonblock, sock.as_ref());
        }
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(errno_ret(EINVAL)), // unreachable
    }
}

/// An empty receive queue: a non-blocking receive reports -EAGAIN at once; a
/// blocking one parks on the socket's read readiness and RE-EXECUTES the
/// syscall when woken (`sock_recvmsg` sleeps in the protocol's wait loop and
/// never returns a spurious 0, which a caller would read as EOF).
pub(super) fn socket_recv_would_block(
    ctx: &mut dyn TrapContext,
    nonblock: bool,
    sock: &crate::socket::SocketFile,
) {
    if nonblock {
        ctx.set_return(errno_ret(EAGAIN));
        return;
    }
    if park_reexecute_on_fd(
        ctx,
        sock,
        narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
    ) {
        return;
    }
    // Kernel-test / nested (recvmmsg) context cannot sleep: surface the
    // retryable condition rather than a fabricated EOF.
    ctx.set_return(errno_ret(EAGAIN));
}
