#[allow(unused_imports)]
use super::*;

/// `sendmsg(fd, msghdr, flags)`. We squash the iovec into a single
/// allocation, call the dispatcher's Send, and report the count.
pub(crate) fn sys_socket_sendmsg(ctx: &mut dyn TrapContext) {
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
    // struct msghdr { void *name; u32 namelen; struct iovec *iov;
    //                 usize iovlen; void *ctrl; usize ctrllen; int flags; }
    // Layout matches Linux x86_64 64-bit.
    // read_user_u64/u32 now use copy_from_user internally (SMAP bracket).
    let name_ptr = read_user_u64(msg_ptr);
    let name_len = read_user_u32(msg_ptr + 8);
    let iov_ptr = read_user_u64(msg_ptr + 16);
    let iov_len = read_user_u64(msg_ptr + 24) as usize;
    // Reassemble into a flat kernel buffer under SMAP bracket.
    // Cap total to MAX_USER_COPY so a user-crafted iovec cannot OOM the heap.
    let mut total = alloc::vec::Vec::new();
    for i in 0..iov_len {
        let base = iov_ptr + (i as u64) * 16;
        let p = read_user_u64(base);
        let l = read_user_u64(base + 8) as usize;
        if p == 0 || l == 0 {
            continue;
        }
        if total.len().saturating_add(l) > MAX_USER_COPY {
            ctx.set_return(SyscallReturn::ok((-(EINVAL_CODE as i64)) as u64));
            return;
        }
        let old_len = total.len();
        total.resize(old_len + l, 0u8);
        // SAFETY: SMAP bracket inside copy_from_user; p is a user VA.
        let _ = unsafe { copy_from_user(&mut total[old_len..], p) };
    }
    #[cfg(feature = "syscall-trace")]
    crate::socket::dbg_dbus_peek("TX", &total);
    let dest = if name_ptr != 0 && name_len >= 2 {
        copy_user_addr(name_ptr, name_len as u64)
    } else {
        None
    };

    // SCM_RIGHTS fd-passing: parse msg_control for an SOL_SOCKET/SCM_RIGHTS
    // ancillary message and resolve each int fd to its file object. AF_UNIX
    // (Wayland) ships shm/dma-buf fds this way.
    let ctrl_ptr = read_user_u64(msg_ptr + 32);
    let ctrl_len = read_user_u64(msg_ptr + 40) as usize;
    let passed_fds = match parse_scm_rights_fds(ctrl_ptr, ctrl_len) {
        Ok(fds) => fds,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    if !passed_fds.is_empty() {
        // SCM_RIGHTS applies to AF_UNIX datagrams too. systemd uses that
        // shape for sd_notify's FDSTORE=1 messages; routing it through the
        // stream-only ring reports ENOTCONN and prevents services from ever
        // completing their READY=1 startup handshake.
        let send =
            if sock.domain == crate::socket::AF_UNIX && sock.kind == crate::socket::SOCK_DGRAM {
                sock.unix_dgram_sendmsg(&total, flags, dest, passed_fds)
            } else {
                sock.unix_sendmsg(&total, passed_fds)
            };
        return match send {
            Ok(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            Err(crate::socket::SockError::WouldBlock) => {
                handler_sys_socket_send::socket_send_would_block(
                    ctx,
                    fd,
                    flags,
                    sock.as_ref(),
                )
            }
            Err(e) => ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64)),
        };
    }

    match sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: &total,
        flags,
        addr: dest,
    }) {
        crate::socket::SocketOpResult::Ok(n) => ctx.set_return(SyscallReturn::ok(n)),
        // Map the real socket error to its errno (EAGAIN/ENOTCONN/EPIPE/…)
        // instead of the bare -1 sentinel (which musl reads as EPERM and
        // libwayland treats as a fatal connection error).
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            handler_sys_socket_send::socket_send_would_block(ctx, fd, flags, sock.as_ref());
        }
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(fail),
    }
}
