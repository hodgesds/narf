#[allow(unused_imports)]
use super::*;

/// `socketpair(domain, type, protocol, int sv[2])` — create a
/// connected pair of AF_UNIX SOCK_STREAM sockets and write the two
/// fds into the user `sv[2]` out-array. The `type` argument may carry
/// SOCK_CLOEXEC / SOCK_NONBLOCK flag bits, which apply to both ends.
pub(crate) fn sys_socketpair(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let domain = args.arg0 as u16;
    let raw_type = args.arg1 as u32;
    let _protocol = args.arg2 as u32;
    let sv_ptr = args.arg3;
    // Peel the SOCK_CLOEXEC / SOCK_NONBLOCK flag bits off the type.
    let kind = raw_type & !(crate::fd::O_CLOEXEC | crate::fd::O_NONBLOCK);
    let cloexec = raw_type & crate::fd::O_CLOEXEC != 0;
    let nonblock = raw_type & crate::fd::O_NONBLOCK != 0;
    // Linux only implements socketpair(2) for AF_UNIX/AF_LOCAL. Match its error
    // order: sock_create rejects an unknown family with -EAFNOSUPPORT; a known
    // family that lacks a ->socketpair op (every non-UNIX family here) is
    // -EOPNOTSUPP; and AF_UNIX with an unsupported type is -ESOCKTNOSUPPORT.
    // STREAM is byte-stream; SEQPACKET and DGRAM retain one record per send.
    let family_known = matches!(
        domain,
        crate::socket::AF_UNIX
            | crate::socket::AF_INET
            | crate::socket::AF_INET6
            | crate::socket::AF_BYPASS
            | crate::socket::AF_NETLINK
    );
    let kind_ok = matches!(
        kind,
        crate::socket::SOCK_STREAM | crate::socket::SOCK_SEQPACKET | crate::socket::SOCK_DGRAM
    );
    if !family_known {
        ctx.set_return(SyscallReturn::ok((-97i64) as u64)); // -EAFNOSUPPORT
        return;
    }
    if domain != crate::socket::AF_UNIX {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // -EOPNOTSUPP
        return;
    }
    if !kind_ok {
        ctx.set_return(SyscallReturn::ok((-94i64) as u64)); // -ESOCKTNOSUPPORT
        return;
    }
    let (a, b) = crate::socket::SocketFile::unix_pair(kind);
    if nonblock {
        a.set_nonblock(true);
        b.set_nonblock(true);
    }
    // Both ends belong to this process; each end's SO_PEERCRED reports the
    // other's owning identity (same process here).
    let cred = current_ucred();
    let groups = current_groups();
    a.set_local_cred(cred);
    b.set_local_cred(cred);
    a.set_local_groups(groups.clone());
    b.set_local_groups(groups);
    crate::socket::SocketFile::cross_peer_creds(&a, &b);
    socket_arc_register(&a);
    socket_arc_register(&b);
    let fd_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
    let status_flags = crate::fd::O_RDWR | if nonblock { crate::fd::O_NONBLOCK } else { 0 };
    let task = current_task_id();
    let mk = |ops: alloc::sync::Arc<crate::socket::SocketFile>| {
        fd::with_table(task, |t| {
            t.open(crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: fd_flags,
                status_flags,
            })
        })
    };
    let fd_a = match mk(a) {
        Some(n) => n,
        None => {
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
            return;
        }
    };
    let fd_b = match mk(b) {
        Some(n) => n,
        None => {
            let _ = fd::with_table(task, |t| t.close(fd_a));
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
            return;
        }
    };
    // Write sv[2] = [fd_a, fd_b] as two native-endian i32.
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&(fd_a as i32).to_ne_bytes());
    buf[4..8].copy_from_slice(&(fd_b as i32).to_ne_bytes());
    // SAFETY: `sv_ptr` is the user `int sv[2]` out-pointer; copy_to_user
    // range-validates the 8-byte destination before writing.
    if unsafe { copy_to_user(sv_ptr, &buf) }.is_err() {
        let _ = fd::with_table(task, |t| {
            t.close(fd_a);
            t.close(fd_b)
        });
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
