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
    let fail = SyscallReturn::ok((-1i64) as u64);
    // Peel the SOCK_CLOEXEC / SOCK_NONBLOCK flag bits off the type.
    let kind = raw_type & !(crate::fd::O_CLOEXEC | crate::fd::O_NONBLOCK);
    let cloexec = raw_type & crate::fd::O_CLOEXEC != 0;
    let nonblock = raw_type & crate::fd::O_NONBLOCK != 0;
    // Linux only implements socketpair(2) for AF_UNIX/AF_LOCAL; other
    // families return EOPNOTSUPP. We back STREAM, SEQPACKET and DGRAM with
    // the same connected AF_UNIX pair — systemd-udev creates a
    // SOCK_DGRAM/SOCK_SEQPACKET worker-IPC pair at startup and self-frames
    // its messages, so byte-stream delivery is sufficient.
    let kind_ok = matches!(
        kind,
        crate::socket::SOCK_STREAM | crate::socket::SOCK_SEQPACKET | crate::socket::SOCK_DGRAM
    );
    if domain != crate::socket::AF_UNIX || !kind_ok {
        ctx.set_return(fail);
        return;
    }
    let (a, b) = crate::socket::SocketFile::unix_stream_pair();
    if nonblock {
        a.set_nonblock(true);
        b.set_nonblock(true);
    }
    // Both ends belong to this process; each end's SO_PEERCRED reports the
    // other's owning identity (same process here).
    let cred = current_ucred();
    a.set_local_cred(cred);
    b.set_local_cred(cred);
    crate::socket::SocketFile::cross_peer_creds(&a, &b);
    socket_arc_register(&a);
    socket_arc_register(&b);
    let fd_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
    let status_flags = if nonblock { crate::fd::O_NONBLOCK } else { 0 };
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
            ctx.set_return(fail);
            return;
        }
    };
    let fd_b = match mk(b) {
        Some(n) => n,
        None => {
            let _ = fd::with_table(task, |t| t.close(fd_a));
            ctx.set_return(fail);
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
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
