#[allow(unused_imports)]
use super::*;

/// `recvmsg(fd, msghdr, flags)`. Reverse of sendmsg.
pub(crate) fn sys_socket_recvmsg(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let msg_ptr = args.arg1;
    let flags = args.arg2 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if msg_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    // read_user_u64/u32 use SMAP bracket internally.
    let name_ptr = read_user_u64(msg_ptr);
    let name_len_ptr = msg_ptr + 8; // namelen lives at offset 8
    let iov_ptr = read_user_u64(msg_ptr + 16);
    let iov_len = read_user_u64(msg_ptr + 24) as usize;
    // Total capacity from iovecs. Cap at MAX_USER_COPY to prevent OOM
    // from a user-crafted iovec with a giant per-slot length.
    let mut total_cap = 0usize;
    for i in 0..iov_len {
        let base = iov_ptr + (i as u64) * 16;
        total_cap = total_cap.saturating_add(read_user_u64(base + 8) as usize);
    }
    if total_cap > MAX_USER_COPY {
        ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
        return;
    }
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
            // Scatter into iovec destinations under SMAP bracket.
            let mut copied = 0;
            for i in 0..iov_len {
                if copied >= n {
                    break;
                }
                let base = iov_ptr + (i as u64) * 16;
                let p = read_user_u64(base);
                let l = read_user_u64(base + 8) as usize;
                let take = core::cmp::min(l, n - copied);
                // SAFETY: p is a user VA; SMAP bracket inside copy_to_user.
                let _ = unsafe { copy_to_user(p, &staging[copied..copied + take]) };
                copied += take;
            }
            // Write peer sockaddr if requested.
            if let (Some(peer), true) = (peer, name_ptr != 0) {
                let mut peer_buf = alloc::vec![0u8; 2 + peer.body.len()];
                let fam_bytes = peer.family.to_le_bytes();
                peer_buf[0] = fam_bytes[0];
                peer_buf[1] = fam_bytes[1];
                peer_buf[2..].copy_from_slice(&peer.body);
                // SAFETY: name_ptr is a user VA.
                let _ = unsafe { copy_to_user(name_ptr, &peer_buf) };
                write_user_u32(name_len_ptr, (peer.body.len() + 2) as u32);
            } else {
                // No source address (connected socket): `msg_namelen` is a kernel
                // OUTPUT field and must be set to 0, not left holding the caller's
                // input buffer size — otherwise a peer-address-reading recvmsg
                // parses garbage from an untouched name buffer.
                write_user_u32(name_len_ptr, 0);
            }

            if sock.domain == crate::socket::AF_NETLINK {
                // Netlink uevent: attach SCM_CREDENTIALS naming the KERNEL as
                // sender (pid/uid/gid = 0). systemd's libudev sets SO_PASSCRED
                // and silently drops any uevent whose recvmsg carries no
                // sender credentials with uid 0 — so this is required for
                // udevd / `udevadm monitor` to accept our broadcasts.
                install_netlink_creds(msg_ptr);
            } else {
                // SCM_RIGHTS: install any passed file objects into this task's
                // fd table and report the new fd numbers in an SOL_SOCKET/
                // SCM_RIGHTS control message. When SO_PASSCRED is set, also
                // attach an SCM_CREDENTIALS cmsg naming the message sender —
                // sd_notify's PID 1 reads $NOTIFY_SOCKET with SO_PASSCRED to
                // learn which service reported READY=1.
                let recv_fds = sock.unix_take_recv_fds();
                let cred = if sock.passcred() {
                    // The stored sender cred carries the sender's OUTER
                    // ProcessId; deliver it in the RECEIVER's PID-namespace view
                    // so it matches the pid the receiver knows. This is
                    // load-bearing for sd_notify: PID 1 rejects a READY=1
                    // datagram whose SCM_CREDENTIALS pid != the service MainPID,
                    // and MainPID is now the child's in-namespace pid (see the
                    // clone-return translation). Identity in the root namespace.
                    let mut c = sock.recvmsg_cred();
                    c.pid = report_pid_to(current_task_id(), c.pid as u64) as u32;
                    Some(c)
                } else {
                    None
                };
                install_recv_ancillary(msg_ptr, recv_fds, cred);
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
            write_user_u32(
                msg_ptr + 48,
                if truncated_full_len.is_some() {
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
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(fail),
    }
}
