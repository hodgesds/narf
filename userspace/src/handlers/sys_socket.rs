#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // The type argument carries optional SOCK_CLOEXEC / SOCK_NONBLOCK flags
    // ORed onto the base type; strip them before categorising the socket
    // (libwayland creates sockets as SOCK_STREAM|SOCK_CLOEXEC, which an
    // unmasked compare reads as an unknown type → bind() fails).
    //
    // `net/socket.c::__sys_socket_create`:
    //
    // ```text
    //     if ((type & ~SOCK_TYPE_MASK) & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
    //             return ERR_PTR(-EINVAL);
    //     type &= SOCK_TYPE_MASK;
    // ```
    //
    // This runs BEFORE `sock_create`, so -EINVAL for an undefined flag bit
    // beats the -EAFNOSUPPORT an unknown family would otherwise report.
    // SOCK_CLOEXEC/SOCK_NONBLOCK are defined as O_CLOEXEC/O_NONBLOCK
    // (include/linux/net.h), so use the shared fd flags rather than
    // restating their values here.
    const SOCK_TYPE_MASK: u32 = 0xf; // include/linux/net.h
    let raw_kind = args.arg1 as u32;
    let type_flags = raw_kind & !SOCK_TYPE_MASK;
    if type_flags & !(crate::fd::O_CLOEXEC | crate::fd::O_NONBLOCK) != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let sock_cloexec = (type_flags & crate::fd::O_CLOEXEC) != 0;
    let sock_nonblock = (type_flags & crate::fd::O_NONBLOCK) != 0;
    let kind = raw_kind & SOCK_TYPE_MASK;
    let (domain, kind, proto) =
        match validate_socket_create(args.arg0, kind, args.arg2, current_task_id()) {
            Ok(v) => v,
            Err(errno) => {
                ctx.set_return(errno_ret(errno));
                return;
            }
        };
    let sock = crate::socket::SocketFile::with_protocol(domain, kind, proto);
    if sock_nonblock {
        // SocketFile carries the shared open-file-description view used by
        // F_GETFL/F_SETFL across dup and SCM_RIGHTS. Keep it in sync with the
        // fd-table status word installed below.
        sock.set_nonblock(true);
    }
    // Stamp the creator's credentials so SO_PEERCRED / SCM_CREDENTIALS on
    // the peer end report this process's real (pid, uid, gid).
    sock.set_local_cred(current_ucred());
    sock.set_local_groups(current_groups());
    // Net-namespace scoping: stamp the creator's net-ns id so the
    // AF_INET bind/port tables are keyed per-ns (two processes in
    // different net-ns can both bind the same addr:port). 0 = host ns.
    let task = current_task_id();
    #[cfg(feature = "container")]
    {
        if let Some(ns) = crate::namespaces::current_net_ns(task) {
            sock.set_net_namespace(ns);
        }
    }
    if domain == crate::socket::AF_PACKET {
        // packet_create registers its protocol hook in the creator's network
        // namespace, so initialise only after the namespace object/id above
        // has been attached to the socket.
        sock.init_packet(proto);
    }
    if domain == crate::socket::AF_NETLINK {
        if let Some(owner) = crate::task::task_get(task) {
            crate::network_daemon::delegate_socket(&owner, &sock);
        }
        // The socket's `f_cred` half of `netlink_net_capable`: rtnetlink
        // changes need CAP_NET_ADMIN from the opener as well as the sender.
        sock.record_opener_net_admin(task);
    }
    let new_fd = match fd::install(task, crate::fd::FdEntry {
            ops: sock.clone(),
            offset: 0,
            flags: if sock_cloexec {
                crate::fd::FD_CLOEXEC
            } else {
                0
            },
            status_flags: crate::fd::O_RDWR
                | if sock_nonblock {
                    crate::fd::O_NONBLOCK
                } else {
                    0
                },
        }) {
        Some(n) => n,
        None => {
            // Linux socket() → sock_map_fd → get_unused_fd_flags: a full
            // per-process descriptor table is -EMFILE.
            ctx.set_return(errno_ret(EMFILE));
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

/// Linux raw-socket creation asks `ns_capable(net->user_ns, CAP_NET_RAW)`,
/// not whether the caller has CAP_NET_RAW in its own user namespace.  A task
/// that unshared only CLONE_NEWUSER must not gain raw access to the initial
/// network namespace; once it also creates a network namespace, that new
/// namespace is owned by its current user namespace and the same check passes.
fn task_net_raw_capable(task: u64) -> bool {
    #[cfg(feature = "container")]
    {
        if let Some(net) = crate::namespaces::current_net_ns(task) {
            return task_ns_capable(task, &net.owner_user_ns(), CAP_NET_RAW);
        }
    }
    task_capable(task, CAP_NET_RAW)
}

/// `sock_create` validation shared by `socket(2)` and `socketpair(2)`, in the
/// order Linux applies it. `kind` has already had SOCK_CLOEXEC/SOCK_NONBLOCK
/// stripped. Returns the (family, type, protocol) the socket is built with:
/// AF_UNIX SOCK_RAW is remapped to SOCK_DGRAM and an INET protocol of 0 is
/// resolved to the type's default, as the family `create` hooks do.
///
/// `net/socket.c::__sock_create`:
///   - `family < 0 || family >= NPROTO` → -EAFNOSUPPORT
///   - `type < 0 || type >= SOCK_MAX`   → -EINVAL
///   - no registered family             → -EAFNOSUPPORT
///
/// then the family's `create`:
///   - `unix_create`: protocol not 0/PF_UNIX → -EPROTONOSUPPORT; a type other
///     than STREAM/SEQPACKET/DGRAM/RAW → -ESOCKTNOSUPPORT.
///   - `inet_create`: protocol outside `[0, IPPROTO_MAX)` → -EINVAL; no
///     `inetsw` entry for the type → -ESOCKTNOSUPPORT; no entry for the
///     protocol (STREAM+UDP, RAW with protocol 0, …) → -EPROTONOSUPPORT;
///     SOCK_RAW without CAP_NET_RAW → -EPERM.
///   - `netlink_create`: a type other than RAW/DGRAM → -ESOCKTNOSUPPORT;
///     protocol outside `[0, MAX_LINKS)` → -EPROTONOSUPPORT.
///
/// AF_INET6 registers TCP and UDP. Raw IPv6 remains unavailable until its
/// checksum and ICMPv6 filtering ABI is implemented; unlike UDP, it must not
/// be advertised as a socket whose operations cannot work.
pub(super) fn validate_socket_create(
    raw_domain: u64,
    kind: u32,
    raw_proto: u64,
    task: u64,
) -> Result<(u16, u32, u32), i64> {
    use crate::socket::{
        AF_BLUETOOTH, AF_BYPASS, AF_INET, AF_INET6, AF_NETLINK, AF_PACKET, AF_UNIX, BTPROTO_HCI,
        BTPROTO_L2CAP, BTPROTO_RFCOMM, BTPROTO_SCO, BT_MAX_PROTO, IPPROTO_ICMP, IPPROTO_TCP,
        IPPROTO_UDP, SOCK_DGRAM, SOCK_PACKET, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM,
    };
    const NPROTO: i32 = 46; // AF_MAX, include/linux/socket.h
    const SOCK_MAX: u32 = 11; // SOCK_PACKET + 1, include/linux/net.h
    const IPPROTO_MAX: i32 = 263; // include/uapi/linux/in.h
    const MAX_LINKS: i32 = 32; // include/uapi/linux/netlink.h
    let family = raw_domain as i32;
    if !(0..NPROTO).contains(&family) {
        return Err(EAFNOSUPPORT);
    }
    if kind >= SOCK_MAX {
        return Err(EINVAL);
    }
    let domain = family as u16;
    let protocol = raw_proto as i32;
    // `__sock_create`: PF_INET + SOCK_PACKET is redirected to PF_PACKET
    // before the family lookup.
    let domain = if domain == AF_INET && kind == SOCK_PACKET {
        AF_PACKET
    } else {
        domain
    };
    match domain {
        AF_UNIX => {
            if protocol != 0 && protocol != AF_UNIX as i32 {
                return Err(EPROTONOSUPPORT);
            }
            match kind {
                SOCK_STREAM | SOCK_SEQPACKET | SOCK_DGRAM => Ok((domain, kind, protocol as u32)),
                // `unix_create`: "Believe it or not BSD has AF_UNIX, SOCK_RAW".
                SOCK_RAW => Ok((domain, SOCK_DGRAM, protocol as u32)),
                _ => Err(ESOCKTNOSUPPORT),
            }
        }
        AF_INET | AF_INET6 => {
            if !(0..IPPROTO_MAX).contains(&protocol) {
                return Err(EINVAL);
            }
            let protocol = protocol as u32;
            match kind {
                SOCK_STREAM => match protocol {
                    0 | IPPROTO_TCP => Ok((domain, kind, IPPROTO_TCP)),
                    _ => Err(EPROTONOSUPPORT),
                },
                SOCK_DGRAM if domain == AF_INET6 => match protocol {
                    0 | IPPROTO_UDP => Ok((domain, kind, IPPROTO_UDP)),
                    _ => Err(EPROTONOSUPPORT),
                },
                SOCK_RAW if domain == AF_INET6 => Err(EAFNOSUPPORT),
                SOCK_DGRAM => match protocol {
                    0 | IPPROTO_UDP => Ok((domain, kind, IPPROTO_UDP)),
                    IPPROTO_ICMP => Ok((domain, kind, protocol)),
                    _ => Err(EPROTONOSUPPORT),
                },
                SOCK_RAW => {
                    if protocol == 0 {
                        return Err(EPROTONOSUPPORT);
                    }
                    if !task_net_raw_capable(task) {
                        return Err(EPERM);
                    }
                    Ok((domain, kind, protocol))
                }
                _ => Err(ESOCKTNOSUPPORT),
            }
        }
        AF_NETLINK => {
            if kind != SOCK_RAW && kind != SOCK_DGRAM {
                return Err(ESOCKTNOSUPPORT);
            }
            if !(0..MAX_LINKS).contains(&protocol) {
                return Err(EPROTONOSUPPORT);
            }
            Ok((domain, kind, protocol as u32))
        }
        AF_PACKET => {
            // packet_create checks authority before type, and treats protocol
            // as an opaque truncated __be16 rather than validating its range.
            if !task_net_raw_capable(task) {
                return Err(EPERM);
            }
            if !matches!(kind, SOCK_DGRAM | SOCK_RAW | SOCK_PACKET) {
                return Err(ESOCKTNOSUPPORT);
            }
            Ok((domain, kind, raw_proto as u32))
        }
        AF_BLUETOOTH => {
            // `bt_sock_create`: protocol outside [0, BT_MAX_PROTO) → -EINVAL;
            // an unregistered protocol → -EPROTONOSUPPORT. Then the per-proto
            // `create`: `hci_sock_create` accepts only SOCK_RAW → otherwise
            // -ESOCKTNOSUPPORT. Only BTPROTO_HCI is registered so far.
            if !(0..BT_MAX_PROTO).contains(&protocol) {
                return Err(EINVAL);
            }
            // Per-protocol socket-type rules (net/bluetooth/*_sock.c create):
            //   HCI    → SOCK_RAW
            //   L2CAP  → SOCK_SEQPACKET/STREAM/DGRAM/RAW
            //   RFCOMM → SOCK_STREAM
            //   SCO    → SOCK_SEQPACKET
            match protocol as u32 {
                BTPROTO_HCI if kind == SOCK_RAW => Ok((domain, kind, BTPROTO_HCI)),
                BTPROTO_L2CAP
                    if matches!(kind, SOCK_SEQPACKET | SOCK_STREAM | SOCK_DGRAM | SOCK_RAW) =>
                {
                    Ok((domain, kind, BTPROTO_L2CAP))
                }
                BTPROTO_RFCOMM if kind == SOCK_STREAM => Ok((domain, kind, BTPROTO_RFCOMM)),
                BTPROTO_SCO if kind == SOCK_SEQPACKET => Ok((domain, kind, BTPROTO_SCO)),
                BTPROTO_HCI | BTPROTO_L2CAP | BTPROTO_RFCOMM | BTPROTO_SCO => {
                    Err(ESOCKTNOSUPPORT)
                }
                _ => Err(EPROTONOSUPPORT),
            }
        }
        AF_BYPASS => Ok((domain, kind, raw_proto as u32)),
        _ => Err(EAFNOSUPPORT),
    }
}
