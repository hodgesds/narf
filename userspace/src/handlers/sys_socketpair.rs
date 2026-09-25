#[allow(unused_imports)]
use super::*;

/// `socketpair(domain, type, protocol, int sv[2])` — create a
/// connected pair of AF_UNIX SOCK_STREAM sockets and write the two
/// fds into the user `sv[2]` out-array. The `type` argument may carry
/// SOCK_CLOEXEC / SOCK_NONBLOCK flag bits, which apply to both ends.
pub(crate) fn sys_socketpair(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let raw_type = args.arg1 as u32;
    let sv_ptr = args.arg3;
    // `net/socket.c::__sys_socketpair`:
    //
    // ```text
    //     flags = type & ~SOCK_TYPE_MASK;
    //     if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
    //             return -EINVAL;
    //     type &= SOCK_TYPE_MASK;
    // ```
    //
    // The flag word is validated FIRST — before the family is looked at —
    // so an undefined bit is -EINVAL even when the domain is also wrong.
    // Without this every unknown bit was silently peeled off and ignored,
    // so a caller probing for a flag this kernel does not implement saw it
    // "succeed" and assumed the semantics it asked for were in effect.
    const SOCK_TYPE_MASK: u32 = 0xf; // include/linux/net.h
    let flags = raw_type & !SOCK_TYPE_MASK;
    if flags & !(crate::fd::O_CLOEXEC | crate::fd::O_NONBLOCK) != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // `__sys_socketpair` creates both ends with `sock_create` first, so the
    // family/type/protocol errors (-EAFNOSUPPORT, -EINVAL, -ESOCKTNOSUPPORT,
    // -EPROTONOSUPPORT, -EPERM) come from the same validation as socket(2).
    // Only AF_UNIX implements `->socketpair`; any other family that creates
    // successfully is -EOPNOTSUPP (`sock_no_socketpair`).
    let (domain, kind, _protocol) = match handler_sys_socket::validate_socket_create(
        args.arg0,
        raw_type & SOCK_TYPE_MASK,
        args.arg2,
        current_task_id(),
    ) {
        Ok(v) => v,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let cloexec = flags & crate::fd::O_CLOEXEC != 0;
    let nonblock = flags & crate::fd::O_NONBLOCK != 0;
    if domain != crate::socket::AF_UNIX {
        ctx.set_return(errno_ret(EOPNOTSUPP));
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
    let fd_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
    let status_flags = crate::fd::O_RDWR | if nonblock { crate::fd::O_NONBLOCK } else { 0 };
    let task = current_task_id();
    let mk = |ops: alloc::sync::Arc<crate::socket::SocketFile>| crate::fd::FdEntry {
        ops,
        offset: 0,
        flags: fd_flags,
        status_flags,
    };
    let (fd_a, fd_b) = match fd::install_pair(task, mk(a), mk(b)) {
        Some(fds) => fds,
        None => {
            ctx.set_return(errno_ret(EMFILE));
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
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
