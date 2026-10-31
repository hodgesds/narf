#[allow(unused_imports)]
use super::*;

const MSG_CMSG_COMPAT: u32 = 0x8000_0000;
const MSG_EOR: u32 = 0x80;
const UIO_MAXIOV: usize = 1024;
const MSGHDR_SIZE: usize = 56;

pub(super) enum SendMsgResult {
    Sent { written: usize, complete: bool },
    WouldBlock,
    Error(i64),
    /// An error that raises no SIGPIPE even when it is EPIPE (a blocking
    /// AF_UNIX stream send woken from its wait; see `unix_stream_send_loop`).
    QuietError(i64),
    /// A blocking stream send left its frame restart-pending: return without
    /// a value. Only the trap-context `sendmsg` path produces it.
    Restart,
}

/// `sendmsg(fd, msghdr, flags)` with Linux's native validation order:
/// compatibility-only flags, descriptor type, complete msghdr/address/iovec
/// import, ancillary import, payload copy, then protocol dispatch.
pub(crate) fn sys_socket_sendmsg(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let msg_ptr = args.arg1;
    let flags = args.arg2 as u32;

    // Native sendmsg never admits the in-kernel compat marker. Linux checks it
    // before fdget(), so it wins even for an invalid descriptor.
    if flags & MSG_CMSG_COMPAT != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let sock = match current_socket_result(fd) {
        Ok(socket) => socket,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // SO_SNDTIMEO: pick up this call's deadline if it is re-executing.
    let resumed = handler_sys_socket_recv::sock_timeo_take(ctx, &sock);
    let blocking_unix_stream = flags & 0x40 == 0
        && !socket_listener_nonblock(current_task_id(), fd, sock.as_ref());
    let wait_ctx = if blocking_unix_stream {
        Some(ctx as &mut dyn TrapContext)
    } else {
        None
    };
    match sendmsg_on_socket(&sock, msg_ptr, flags, false, wait_ctx, resumed) {
        SendMsgResult::Sent { written, .. } => ctx.set_return(SyscallReturn::ok(written as u64)),
        SendMsgResult::Restart => {}
        SendMsgResult::QuietError(errno) => ctx.set_return(errno_ret(errno)),
        SendMsgResult::WouldBlock => {
            handler_sys_socket_send::socket_send_would_block(ctx, fd, flags, sock.as_ref(), resumed)
        }
        SendMsgResult::Error(errno) => {
            // Broken-pipe sendmsg raises SIGPIPE to the sender unless
            // MSG_NOSIGNAL is set (Linux sk_stream_error net/core/stream.c:194,
            // unix_stream_sendmsg net/unix/af_unix.c:2500). errno 32 == EPIPE.
            // Datagram/seqpacket EPIPEs never signal (see sys_socket_send).
            if errno == EPIPE && flags & crate::socket::MSG_NOSIGNAL == 0 && sock.epipe_raises_sigpipe() {
                raise_signal_pending(current_task_id(), 13); // SIGPIPE
            }
            ctx.set_return(errno_ret(errno));
        }
    }
}

/// Import and send one native `user_msghdr` through an already-resolved
/// socket. `allow_msg_eor` is true only for sendmmsg, matching Linux's
/// `allowed_msghdr_flags` argument.
pub(super) fn sendmsg_on_socket(
    sock: &alloc::sync::Arc<crate::socket::SocketFile>,
    msg_ptr: u64,
    mut flags: u32,
    allow_msg_eor: bool,
    wait_ctx: Option<&mut dyn TrapContext>,
    resumed: Option<u64>,
) -> SendMsgResult {
    let mut header = [0u8; MSGHDR_SIZE];
    // SAFETY: copy_from_user validates all 56 bytes before copying them.
    if unsafe { copy_from_user(&mut header, msg_ptr) }.is_err() {
        return SendMsgResult::Error(14); // EFAULT
    }

    let name_ptr = field_u64(&header, 0);
    let name_len = field_u32(&header, 8) as i32;
    let iov_ptr = field_u64(&header, 16);
    let iov_len_u64 = field_u64(&header, 24);
    let ctrl_ptr = field_u64(&header, 32);
    let ctrl_len_u64 = field_u64(&header, 40);
    let header_flags = field_u32(&header, 48);

    // __copy_msghdr imports/clamps the optional address before rejecting an
    // oversized iov count.
    let dest = match import_sendmsg_addr(name_ptr, name_len) {
        Ok(addr) => addr,
        Err(errno) => return SendMsgResult::Error(errno),
    };
    if iov_len_u64 > UIO_MAXIOV as u64 {
        return SendMsgResult::Error(90); // EMSGSIZE
    }
    let iov_len = iov_len_u64 as usize;
    let iov_bytes = match iov_len.checked_mul(16) {
        Some(bytes) => bytes,
        None => return SendMsgResult::Error(14), // EFAULT
    };
    let iov_raw = if iov_bytes == 0 {
        alloc::vec::Vec::new()
    } else {
        // SAFETY: complete iovec-array import; invalid array pointer is EFAULT.
        match unsafe { copy_from_user_vec(iov_ptr, iov_bytes) } {
            Ok(bytes) => bytes,
            Err(_) => return SendMsgResult::Error(14),
        }
    };

    // Import all vector descriptors and validate their source ranges before
    // ancillary processing, as Linux import_iovec does. Actual payload copying
    // remains deferred until after the control buffer has been imported.
    let mut vectors = alloc::vec::Vec::new();
    if vectors.try_reserve_exact(iov_len).is_err() {
        return SendMsgResult::Error(12); // ENOMEM
    }
    let mut total_len = 0usize;
    for i in 0..iov_len {
        let off = i * 16;
        let ptr = u64::from_ne_bytes(iov_raw[off..off + 8].try_into().unwrap());
        let len = u64::from_ne_bytes(iov_raw[off + 8..off + 16].try_into().unwrap());
        // `iovec_from_user`: a negative (as ssize_t) iov_len is -EINVAL; the
        // running total is then clamped to MAX_RW_COUNT (here MAX_USER_COPY)
        // rather than rejected, so an oversized stream send is a short send.
        if (len as i64) < 0 {
            return SendMsgResult::Error(EINVAL);
        }
        let len = core::cmp::min(len as usize, MAX_USER_COPY - total_len);
        if len != 0 && validate_user_range(ptr, len).is_err() {
            return SendMsgResult::Error(14); // EFAULT
        }
        total_len += len;
        vectors.push((ptr, len));
    }

    // Linux rejects an unrepresentable control length as ENOBUFS before
    // attempting the control copy. NARF also bounds the allocation at its
    // documented per-syscall copy ceiling, with the same resource errno.
    if ctrl_len_u64 > i32::MAX as u64 || ctrl_len_u64 > MAX_USER_COPY as u64 {
        return SendMsgResult::Error(105); // ENOBUFS
    }
    let ancillary = match parse_scm_send_ancillary(ctrl_ptr, ctrl_len_u64 as usize) {
        Ok(ancillary) => ancillary,
        Err(errno) => return SendMsgResult::Error(errno),
    };
    // An IP_PKTINFO/IPV6_PKTINFO source override applies to the AF_INET/INET6
    // datagram send that follows; stash it for the send path to consume.
    if let Some(pi) = ancillary.src_override {
        if matches!(
            sock.domain,
            crate::socket::AF_INET | crate::socket::AF_INET6
        ) {
            sock.stash_send_pktinfo(pi);
        }
    }

    let mut total = alloc::vec::Vec::new();
    if total.try_reserve_exact(total_len).is_err() {
        return SendMsgResult::Error(12); // ENOMEM
    }
    for (ptr, len) in vectors {
        if len == 0 {
            continue;
        }
        let old_len = total.len();
        total.resize(old_len + len, 0);
        // SAFETY: the range was validated above; the guarded copy still catches
        // an unmap race and reports EFAULT rather than publishing partial data.
        if unsafe { copy_from_user(&mut total[old_len..], ptr) }.is_err() {
            return SendMsgResult::Error(14);
        }
    }

    if allow_msg_eor {
        flags |= header_flags & MSG_EOR;
    }
    #[cfg(feature = "syscall-trace")]
    crate::socket::dbg_dbus_peek("TX", &total);

    // SCM_RIGHTS is an AF_UNIX facility. `__scm_send` rejects it for any
    // other family and `ip_cmsg_send` / `sock_cmsg_send` (TCP, UDP) fall to
    // their default arm: -EINVAL, not the -ENOTCONN of the unix send path.
    if !ancillary.fds.is_empty() && sock.domain != crate::socket::AF_UNIX {
        return SendMsgResult::Error(EINVAL);
    }
    // A blocking AF_UNIX stream send must queue the entire iovec payload,
    // waiting in place for its peer to drain whenever a bounded stream ring
    // fills. SCM_RIGHTS and an explicit SCM_CREDENTIALS record ride on the
    // first queued unit only.
    if sock.domain == crate::socket::AF_UNIX
        && sock.kind == crate::socket::SOCK_STREAM
        && dest.is_none()
        // `do_send` owns AF_UNIX's MSG_OOB rejection.  Do not bypass it with
        // the blocking continuation path.
        && flags & crate::socket::MSG_OOB == 0
    {
        if let Some(ctx) = wait_ctx {
            return unix_stream_sendmsg_all(
                ctx,
                sock,
                &total,
                ancillary.fds,
                ancillary.cred,
                resumed,
            );
        }
    }
    if !ancillary.fds.is_empty()
        || (ancillary.cred.is_some() && sock.domain == crate::socket::AF_UNIX)
    {
        // A *connected* AF_UNIX datagram socketpair delivers over its crossed
        // rings, not the address registry — so its SCM_RIGHTS send goes through
        // `unix_sendmsg` (which frames a datagram record + fds for SOCK_DGRAM),
        // exactly as `dispatch_op` reroutes the no-fd connected-datagram case.
        // Only a bound/named datagram (destination via addr or connect) uses
        // `unix_dgram_sendmsg`. Without this split, systemd's `netns_storage_socket`
        // (a SOCK_DGRAM socketpair) hit `unix_dgram_sendmsg`'s address dispatcher,
        // which has no destination for a connected pair and returned -ENOTCONN —
        // failing every `PrivateNetwork=` service with EXIT_NETWORK.
        let result = if sock.domain == crate::socket::AF_UNIX
            && sock.kind == crate::socket::SOCK_DGRAM
            && !sock.is_unix_connected()
        {
            sock.unix_dgram_sendmsg(&total, flags, dest, ancillary.fds, ancillary.cred)
        } else {
            sock.unix_sendmsg(&total, ancillary.fds, ancillary.cred)
        };
        return match result {
            Ok(n) => SendMsgResult::Sent {
                written: n,
                complete: n >= total_len,
            },
            Err(crate::socket::SockError::WouldBlock) => SendMsgResult::WouldBlock,
            Err(error) => SendMsgResult::Error(error.errno() as i64),
        };
    }

    if let Some(cred) = ancillary.cred {
        if sock.domain == crate::socket::AF_NETLINK {
            let result = sock.netlink_sendmsg_with_cred(&total, flags, dest, cred);
            return match result {
                crate::socket::SocketOpResult::Ok(n) => SendMsgResult::Sent {
                    written: n as usize,
                    complete: n as usize >= total_len,
                },
                crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
                    SendMsgResult::WouldBlock
                }
                crate::socket::SocketOpResult::Err(error) => {
                    SendMsgResult::Error(error.errno() as i64)
                }
                _ => SendMsgResult::Error(EINVAL),
            };
        }
    }

    // `SOL_UDP` records (UDP_SEGMENT) are the UDP send path's to apply, at
    // the point `udp_sendmsg` / `udpv6_sendmsg` call `udp_cmsg_send`. Clear
    // the per-task slot afterwards whichever way the send ended, so it can
    // never reach a later send(2)/sendto(2).
    let udp_cmsg = sock.is_udp() && ancillary.udp_gso.is_some();
    if udp_cmsg {
        if let Some(gso) = ancillary.udp_gso {
            sock.stash_send_udp_gso(gso);
        }
    }
    if let Some(txtime) = ancillary.txtime {
        if !sock.txtime_enabled() {
            if udp_cmsg {
                let _ = sock.take_send_udp_gso();
            }
            return SendMsgResult::Error(EINVAL);
        }
        sock.stash_send_txtime(txtime);
    }
    let result = sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: &total,
        flags,
        addr: dest,
    });
    if udp_cmsg {
        let _ = sock.take_send_udp_gso();
    }
    if ancillary.txtime.is_some() {
        let _ = sock.take_send_txtime();
    }
    match result {
        crate::socket::SocketOpResult::Ok(n) => SendMsgResult::Sent {
            written: n as usize,
            complete: n as usize >= total_len,
        },
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            SendMsgResult::WouldBlock
        }
        crate::socket::SocketOpResult::Err(error) => SendMsgResult::Error(error.errno() as i64),
        _ => SendMsgResult::Error(22),
    }
}

/// Finish a blocking AF_UNIX stream `sendmsg` with
/// [`handler_sys_socket_send::unix_stream_send_loop`], which waits in place,
/// so `done` and the fds' first-unit-only attachment survive every wait.
/// The generic `sendmsg_on_socket` path intentionally remains one attempt so
/// `sendmmsg` preserves its per-message short-write behaviour; only the
/// ordinary blocking syscall supplies a trap context and enters this loop.
fn unix_stream_sendmsg_all(
    ctx: &mut dyn TrapContext,
    sock: &alloc::sync::Arc<crate::socket::SocketFile>,
    total: &[u8],
    fds: alloc::vec::Vec<crate::socket::ScmRightsFile>,
    explicit_cred: Option<crate::socket::Ucred>,
    resumed_timeo: Option<u64>,
) -> SendMsgResult {
    use handler_sys_socket_send::UnixSend;

    // `unix_scm_to_skb(&scm, skb, !fds_sent)`: the rights go out with the
    // first unit that is queued. A first attempt that queues nothing drops
    // what it was handed, so it gets a copy until one succeeds.
    let mut fds = Some(fds);
    let outcome =
        handler_sys_socket_send::unix_stream_send_loop(ctx, sock, total.len(), resumed_timeo, |done| {
            let unit_fds = match (&fds, done) {
                (Some(f), 0) => f.clone(),
                _ => alloc::vec::Vec::new(),
            };
            let cred = (done == 0).then_some(explicit_cred).flatten();
            let n = sock.unix_sendmsg(&total[done..], unit_fds, cred)?;
            if n > 0 {
                fds = None;
            }
            Ok(n)
        });
    match outcome {
        UnixSend::Done(written) => SendMsgResult::Sent {
            written,
            complete: written == total.len(),
        },
        UnixSend::Restart => SendMsgResult::Restart,
        UnixSend::Err { err, out_pipe } => {
            if out_pipe {
                SendMsgResult::Error(err.errno() as i64)
            } else {
                SendMsgResult::QuietError(err.errno() as i64)
            }
        }
    }
}

fn import_sendmsg_addr(ptr: u64, signed_len: i32) -> Result<Option<crate::socket::SockAddr>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    if signed_len < 0 {
        return Err(EINVAL);
    }
    let len = core::cmp::min(signed_len as usize, 128);
    if len == 0 {
        return Ok(None);
    }
    let mut bytes = alloc::vec![0u8; len];
    // SAFETY: guarded import of the clamped sockaddr_storage prefix.
    if unsafe { copy_from_user(&mut bytes, ptr) }.is_err() {
        return Err(EFAULT);
    }
    if len < 2 {
        return Err(EINVAL);
    }
    Ok(Some(crate::socket::SockAddr {
        family: u16::from_ne_bytes([bytes[0], bytes[1]]),
        body: bytes[2..].to_vec(),
    }))
}

#[inline]
fn field_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[inline]
fn field_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
