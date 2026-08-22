#[allow(unused_imports)]
use super::*;

/// `getsockopt(fd, level, optname, opt_val_out, opt_len_inout)`.
/// Linux ref: net/socket.c:SYSCALL_DEFINE5(getsockopt, ...).
pub(crate) fn sys_socket_getsockopt(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let level = args.arg1 as u32;
    let name = args.arg2 as u32;
    let val_ptr = args.arg3;
    let len_ptr = args.arg4;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Read the in/out length field via SMAP bracket.
    let in_len = if len_ptr != 0 {
        read_user_u32(len_ptr) as usize
    } else {
        0
    };
    // NETLINK_LIST_MEMBERSHIPS is a length-query option: Linux answers a
    // `getsockopt(SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, NULL, &len)` (optval
    // NULL, *optlen 0) by writing the required bitmap byte length into optlen
    // and returning 0 — the caller then allocates and issues a second call.
    // sd-netlink's netlink_socket_get_multicast_groups() runs exactly this
    // probe on every sd_netlink_open(); the generic `val_ptr==0 || in_len==0`
    // rejection below turned it into -1 (== -EPERM to libc), which surfaced as
    // systemd's "Failed to open netlink, ignoring: Operation not permitted".
    if level == crate::socket::SOL_NETLINK && name == crate::socket::NETLINK_LIST_MEMBERSHIPS {
        // The optlen out-parameter is mandatory (EFAULT without it).
        if len_ptr == 0 {
            const EFAULT: i64 = 14;
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
        let required = sock.netlink_list_memberships_len();
        // Fill the bitmap only up to the caller-provided buffer; the probe
        // form (val_ptr == 0 or in_len == 0) writes nothing but still reports
        // the required length so the next call can size its allocation.
        let copy_len = if val_ptr != 0 {
            core::cmp::min(required, in_len)
        } else {
            0
        };
        if copy_len > 0 {
            if validate_user_range(val_ptr, copy_len).is_err() {
                ctx.set_return(fail);
                return;
            }
            let mut buf = alloc::vec![0u8; copy_len];
            let _ = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
                level,
                name,
                buf: &mut buf,
            });
            // SAFETY: val_ptr was range-validated to hold copy_len bytes.
            let _ = unsafe { copy_to_user(val_ptr, &buf[..copy_len]) };
        }
        write_user_u32(len_ptr, required as u32);
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if val_ptr == 0 || in_len == 0 {
        ctx.set_return(fail);
        return;
    }
    // Optional Unix-peer metadata needs a typed "protocol option unavailable"
    // result. The generic unknown-option sentinel is -1 (EPERM to libc) and is
    // treated as fatal.
    if level == crate::socket::SOL_SOCKET
        && matches!(
            name,
            crate::socket::SO_PEERSEC | crate::socket::SO_PEERPIDFD
        )
    {
        const ENOPROTOOPT: i64 = 92;
        ctx.set_return(SyscallReturn::ok((-ENOPROTOOPT) as u64));
        return;
    }
    // Validate the output range before allocating — prevents OOM from a
    // user-supplied in_len larger than MAX_USER_COPY.
    if validate_user_range(val_ptr, in_len).is_err() {
        ctx.set_return(fail);
        return;
    }
    let mut buf = alloc::vec![0u8; in_len];
    let result = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level,
        name,
        buf: &mut buf,
    });
    match result {
        crate::socket::SocketOpResult::OptValue { n } => {
            // SO_PEERCRED reports `struct ucred { pid, uid, gid }` with the
            // peer's OUTER ProcessId (stamped at connect/accept). Translate the
            // pid field into the READER's PID namespace view before handing it
            // back — dbus-broker et al. compare it against pids they hold.
            // Identity in the root namespace.
            const SOL_SOCKET: u32 = 1;
            if level == SOL_SOCKET && name == crate::socket::SO_PEERCRED && n >= 12 {
                let cred = report_ucred_to(
                    current_task_id(),
                    crate::socket::Ucred {
                        pid: u32::from_ne_bytes(buf[0..4].try_into().unwrap()),
                        uid: u32::from_ne_bytes(buf[4..8].try_into().unwrap()),
                        gid: u32::from_ne_bytes(buf[8..12].try_into().unwrap()),
                    },
                );
                buf[0..4].copy_from_slice(&cred.pid.to_ne_bytes());
                buf[4..8].copy_from_slice(&cred.uid.to_ne_bytes());
                buf[8..12].copy_from_slice(&cred.gid.to_ne_bytes());
            }
            if level == SOL_SOCKET && name == crate::socket::SO_PEERGROUPS {
                let raw: alloc::vec::Vec<u32> = buf[..n]
                    .chunks_exact(4)
                    .map(|chunk| u32::from_ne_bytes(chunk.try_into().unwrap()))
                    .collect();
                let groups = report_groups_to(current_task_id(), &raw);
                let translated_n = groups.len() * 4;
                for (slot, gid) in buf[..translated_n].chunks_exact_mut(4).zip(groups) {
                    slot.copy_from_slice(&gid.to_ne_bytes());
                }
                write_user_u32(len_ptr, translated_n as u32);
                // SAFETY: val_ptr was range-validated above.
                let _ = unsafe { copy_to_user(val_ptr, &buf[..translated_n]) };
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            // Write value + updated optlen back to user under SMAP bracket.
            // SAFETY: val_ptr from userspace; AS active.
            let _ = unsafe { copy_to_user(val_ptr, &buf[..n]) };
            write_user_u32(len_ptr, n as u32);
            ctx.set_return(SyscallReturn::ok(0));
        }
        crate::socket::SocketOpResult::Err(e) => {
            // SO_PEERGROUPS on ERANGE: Linux writes the required byte length
            // into *optlen so the caller can grow its buffer and retry
            // (net/core/sock.c: `put_user(len, optlen)` then `-ERANGE`).
            // dbus-broker relies on this — `sockopt_get_peergroups` probes with
            // an 8-slot buffer and, for a user in >7 supplementary groups, reads
            // the returned optlen to size the retry. Without the writeback the
            // retry reuses the same too-small size, ERANGEs again, and the
            // broker rejects the peer with a fatal error, taking the session bus
            // down (the greeter user has ≤7 groups, so only real logins hit it).
            // The errno itself (ERANGE = 34) is already correct; only the
            // optlen out-parameter was missing.
            if level == crate::socket::SOL_SOCKET
                && name == crate::socket::SO_PEERGROUPS
                && matches!(e, crate::socket::SockError::Range)
            {
                // `needed` mirrors the socket handler's own `groups.len() * 4`
                // gate; group-id namespace translation is 1:1, so this size is
                // sufficient for the (translated) success reply on retry.
                let needed = sock.peer_groups().len().saturating_mul(4);
                write_user_u32(len_ptr, needed as u32);
            }
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(fail),
    }
}
