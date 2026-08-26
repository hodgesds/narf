#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let domain = args.arg0 as u16;
    // The type argument carries optional SOCK_CLOEXEC / SOCK_NONBLOCK flags
    // ORed onto the base type; strip them before categorising the socket
    // (libwayland creates sockets as SOCK_STREAM|SOCK_CLOEXEC, which an
    // unmasked compare reads as an unknown type → bind() fails).
    const SOCK_CLOEXEC: u32 = 0x8_0000;
    const SOCK_NONBLOCK: u32 = 0x800;
    let raw_kind = args.arg1 as u32;
    let sock_cloexec = (raw_kind & SOCK_CLOEXEC) != 0;
    let sock_nonblock = (raw_kind & SOCK_NONBLOCK) != 0;
    let kind = raw_kind & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
    let proto = args.arg2 as u32;
    // Reject unknown families up front. Linux `__sock_create` returns
    // -EAFNOSUPPORT when no registered net_proto_family matches the domain.
    if !matches!(
        domain,
        crate::socket::AF_UNIX
            | crate::socket::AF_INET
            | crate::socket::AF_INET6
            | crate::socket::AF_BYPASS
            | crate::socket::AF_NETLINK
    ) {
        ctx.set_return(SyscallReturn::ok((-97i64) as u64)); // -EAFNOSUPPORT
        return;
    }
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
    // PID 1 configures only the initial namespace's synthetic loopback during
    // early systemd boot. Keep the authority kernel-held and interface-bound:
    // no other route socket receives an ambient administrative capability.
    if domain == crate::socket::AF_NETLINK
        && proto == crate::socket::NETLINK_ROUTE
        && sock.net_ns_id() == 0
        && task_to_pid_raw(task) == Some(1)
        && sock
            .delegate_netlink_admin(narf_net::initial_loopback_admin())
            .is_err()
    {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    socket_arc_register(&sock);
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
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}
