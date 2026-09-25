#[allow(unused_imports)]
use super::*;

/// `recvmsg(fd, msghdr, flags)`. Reverse of sendmsg.
pub(crate) fn sys_socket_recvmsg(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let msg_ptr = args.arg1;
    let flags = args.arg2 as u32;
    // Linux __sys_recvmsg: sockfd_lookup_light → -EBADF / -ENOTSOCK, then
    // ___sys_recvmsg's copy_msghdr_from_user faults on a NULL/bad msg → -EFAULT.
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if msg_ptr == 0 {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    // `copy_msghdr_from_user` / `__copy_msghdr` / `import_iovec`: every
    // header check runs BEFORE the protocol dequeues anything, so a bad
    // argument never consumes a datagram.
    //   - a faulting msghdr or iovec array        → -EFAULT
    //   - msg_namelen < 0                         → -EINVAL
    //   - msg_iovlen > UIO_MAXIOV                 → -EMSGSIZE
    //   - an iov_len < 0 (as ssize_t)             → -EINVAL
    //   - an iov_base range failing access_ok    → -EFAULT
    // The iov total is clamped (MAX_RW_COUNT in Linux), never rejected.
    let mut hdr = [0u8; 56];
    // SAFETY: copy_from_user range-validates `msg_ptr` and SMAP-brackets it.
    if unsafe { copy_from_user(&mut hdr, msg_ptr) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    let field = |off: usize| u64::from_ne_bytes(hdr[off..off + 8].try_into().unwrap());
    let name_ptr = field(0);
    let name_len_ptr = msg_ptr + 8; // namelen lives at offset 8
    if name_ptr != 0 && (i32::from_ne_bytes(hdr[8..12].try_into().unwrap())) < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let iov_ptr = field(16);
    let iov_len = field(24) as usize;
    const UIO_MAXIOV: usize = 1024;
    if iov_len > UIO_MAXIOV {
        ctx.set_return(errno_ret(EMSGSIZE));
        return;
    }
    let mut iovs = alloc::vec![0u8; iov_len * 16];
    // SAFETY: copy_from_user range-validates the iovec array (a NULL
    // `msg_iov` with a non-zero `msg_iovlen` included).
    if iov_len != 0 && unsafe { copy_from_user(&mut iovs, iov_ptr) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    let mut segs: alloc::vec::Vec<(u64, usize)> = alloc::vec::Vec::with_capacity(iov_len);
    let mut total_cap = 0usize;
    for chunk in iovs.chunks_exact(16) {
        let base = u64::from_ne_bytes(chunk[0..8].try_into().unwrap());
        let len = u64::from_ne_bytes(chunk[8..16].try_into().unwrap());
        if (len as i64) < 0 {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
        let len = core::cmp::min(len as usize, MAX_USER_COPY - total_cap);
        if len != 0 && validate_user_range(base, len).is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        total_cap += len;
        segs.push((base, len));
    }
    const MSG_DONTWAIT: u32 = 0x40;
    let nonblock = (flags & (MSG_DONTWAIT | crate::socket::MSG_ERRQUEUE)) != 0
        || socket_listener_nonblock(current_task_id(), fd, sock.as_ref());
    let mut staging = alloc::vec![0u8; total_cap];
    let result = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut staging,
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
            #[cfg(feature = "syscall-trace")]
            crate::socket::dbg_dbus_peek("RX", &staging[..n]);
            // Kernel output field: clear caller stack contents before
            // ancillary/data truncation paths OR their flags into it.
            write_user_u32(msg_ptr + 48, 0);
            // A fault after the record was dequeued fails the call; drop the
            // record's rights/credentials with it so a later recvmsg cannot
            // inherit ancillary data from the wrong message (as recv() does).
            let fail = |ctx: &mut dyn TrapContext, errno: i64| {
                drop(sock.unix_take_recv_fds());
                let _ = sock.recvmsg_cred();
                ctx.set_return(errno_ret(errno));
            };
            // Scatter into iovec destinations under SMAP bracket.
            let mut copied = 0;
            for &(p, l) in &segs {
                if copied >= n {
                    break;
                }
                let take = core::cmp::min(l, n - copied);
                // SAFETY: p is a user VA; SMAP bracket inside copy_to_user.
                if unsafe { copy_to_user(p, &staging[copied..copied + take]) }.is_err() {
                    fail(ctx, EFAULT);
                    return;
                }
                copied += take;
            }
            // Source address: `___sys_recvmsg` runs `move_addr_to_user` only
            // when `msg_name` is non-NULL. It copies at most the caller's
            // `msg_namelen` bytes and stores the full length (0 when the
            // protocol reports no source, e.g. a connected stream) so a
            // caller never parses a stale name buffer.
            if name_ptr != 0 {
                if let Err(errno) = move_addr_to_user(peer.as_ref(), name_ptr, name_len_ptr) {
                    fail(ctx, errno);
                    return;
                }
            }

            if sock.domain == crate::socket::AF_NETLINK {
                // Netlink uevent: attach SCM_CREDENTIALS naming the KERNEL as
                // sender (pid/uid/gid = 0). systemd's libudev sets SO_PASSCRED
                // and silently drops any uevent whose recvmsg carries no
                // sender credentials with uid 0 — so this is required for
                // udevd / `udevadm monitor` to accept our broadcasts.
                install_netlink_ancillary(msg_ptr, sock.netlink_pktinfo());
            } else {
                // SCM_RIGHTS: install any passed file objects into this task's
                // fd table and report the new fd numbers in an SOL_SOCKET/
                // SCM_RIGHTS control message. When SO_PASSCRED is set, also
                // attach an SCM_CREDENTIALS cmsg naming the message sender —
                // sd_notify's PID 1 reads $NOTIFY_SOCKET with SO_PASSCRED to
                // learn which service reported READY=1.
                let recv_fds = sock.unix_take_recv_fds();
                // Consume the per-record credential even when SO_PASSCRED is
                // off; otherwise the next recvmsg could observe stale sender
                // identity from this record.
                let message_cred = sock.recvmsg_cred();
                let cred = if sock.passcred() {
                    // The stored sender cred carries the sender's OUTER
                    // ProcessId; deliver it in the RECEIVER's PID-namespace view
                    // so it matches the pid the receiver knows. This is
                    // load-bearing for sd_notify: PID 1 rejects a READY=1
                    // datagram whose SCM_CREDENTIALS pid != the service MainPID,
                    // and MainPID is now the child's in-namespace pid (see the
                    // clone-return translation). Identity in the root namespace.
                    Some(report_ucred_to(current_task_id(), message_cred))
                } else {
                    None
                };
                const MSG_CMSG_CLOEXEC: u32 = 0x4000_0000;
                let ancillary_truncated =
                    install_recv_ancillary(msg_ptr, recv_fds, cred, flags & MSG_CMSG_CLOEXEC != 0);
                // Preserve this for the msg_flags write below.
                if ancillary_truncated {
                    write_user_u32(msg_ptr + 48, 0x8); // MSG_CTRUNC
                }
            }

            // `msg_flags` (msghdr offset 48) is a kernel OUTPUT field — Linux
            // always sets it on return (0, or MSG_TRUNC/MSG_CTRUNC/MSG_EOR).
            // NARF left it untouched, so it held whatever the caller's stack
            // had. libdbus's `_dbus_read_socket_with_unix_fds` checks
            // `msg_flags & MSG_CTRUNC` and, if set, treats it as a SERIOUS error
            // ("lost fds") — corrupting the connection right after the Hello
            // reply, so the next message it marshalled/sent came out garbage
            // (a lone 0x71 byte) and the bus dropped it → no KDE session bus.
            // We deliver the whole datagram/stream chunk and never truncate
            // ancillary data here, so the correct value is 0.
            let existing_flags = read_user_u32(msg_ptr + 48);
            write_user_u32(
                msg_ptr + 48,
                existing_flags
                    | if truncated_full_len.is_some() {
                        crate::socket::MSG_TRUNC
                    } else {
                        0
                    },
            );

            let returned = if flags & crate::socket::MSG_TRUNC != 0 {
                truncated_full_len.unwrap_or(n)
            } else {
                n
            };
            ctx.set_return(SyscallReturn::ok(returned as u64));
        }
        // Map the real socket error to its errno. A non-blocking recv with no
        // data must report EAGAIN, not the bare -1 sentinel (which musl maps to
        // EPERM); libwayland's connection reader treats anything but EAGAIN as a
        // fatal "failed to process Wayland connection".
        // An empty queue on a blocking socket sleeps (`sock_recvmsg`), it
        // does not surface -EAGAIN.
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            handler_sys_socket_recv::socket_recv_would_block(ctx, nonblock, sock.as_ref());
        }
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(errno_ret(EINVAL)), // unreachable
    }
}
