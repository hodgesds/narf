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
    // Linux __sys_getsockopt: sockfd_lookup_light → -EBADF / -ENOTSOCK, then
    // -EFAULT for a faulting optval/optlen, then the option handler's errno
    // (-ENOPROTOOPT for an unknown option, -EINVAL, …).
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // `do_sock_getsockopt`: `get_user(len, optlen)` faults → -EFAULT (a NULL
    // optlen included), then `len < 0` → -EINVAL.
    let mut len_raw = [0u8; 4];
    // SAFETY: copy_from_user range-validates `len_ptr` and SMAP-brackets the read.
    if unsafe { copy_from_user(&mut len_raw, len_ptr) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    let in_len_signed = i32::from_ne_bytes(len_raw);
    if in_len_signed < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let in_len = in_len_signed as usize;
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
                ctx.set_return(errno_ret(EFAULT));
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
    // Optional Unix-peer metadata needs a typed "protocol option unavailable"
    // result. The generic unknown-option sentinel is -1 (EPERM to libc) and is
    // treated as fatal.
    if level == crate::socket::SOL_SOCKET
        && matches!(
            name,
            crate::socket::SO_PEERSEC | crate::socket::SO_PEERPIDFD
        )
    {
        ctx.set_return(SyscallReturn::ok((-ENOPROTOOPT) as u64));
        return;
    }
    // Every option handler copies at most `min(len, sizeof(value))` bytes, so
    // the kernel staging buffer never needs to exceed the largest value NARF
    // produces (SO_PEERGROUPS: NGROUPS_MAX gids). SO_PEERCRED is staged at
    // full width so its pid can be namespace-translated before truncation.
    const GETSOCKOPT_MAX_STAGE: usize = 65536 * 4;
    let stage_len = if level == crate::socket::SOL_SOCKET && name == crate::socket::SO_PEERCRED {
        core::cmp::max(in_len, 12)
    } else {
        core::cmp::min(in_len, GETSOCKOPT_MAX_STAGE)
    };
    let mut buf = alloc::vec![0u8; stage_len];
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
                ctx.set_return(copy_sockopt_out(val_ptr, len_ptr, &buf[..translated_n]));
                return;
            }
            // Write value + updated optlen back to user under SMAP bracket,
            // never more than the caller's optlen.
            let n = core::cmp::min(n, in_len);
            ctx.set_return(copy_sockopt_out(val_ptr, len_ptr, &buf[..n]));
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
        _ => ctx.set_return(errno_ret(EINVAL)), // unreachable
    }
}

/// Copy a getsockopt value and its length back to the caller. Linux
/// `sk_getsockopt` & co. check both `copy_to_sockptr` calls, so a faulting
/// optval or optlen is -EFAULT rather than a silent success.
fn copy_sockopt_out(val_ptr: u64, len_ptr: u64, value: &[u8]) -> SyscallReturn {
    // SAFETY: copy_to_user range-validates the user address and SMAP-brackets
    // the write; a zero-length value touches nothing.
    if !value.is_empty() && unsafe { copy_to_user(val_ptr, value) }.is_err() {
        return errno_ret(EFAULT);
    }
    // SAFETY: as above, for the 4-byte optlen out-parameter.
    if unsafe { copy_to_user(len_ptr, &(value.len() as u32).to_ne_bytes()) }.is_err() {
        return errno_ret(EFAULT);
    }
    SyscallReturn::ok(0)
}
