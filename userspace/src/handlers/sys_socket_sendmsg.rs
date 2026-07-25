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
    let passed_fds = parse_scm_rights_fds(ctrl_ptr, ctrl_len);
    if !passed_fds.is_empty() {
        // fd-carrying send → AF_UNIX stream path.
        return match sock.unix_sendmsg(&total, passed_fds) {
            Ok(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
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
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(fail),
    }
}
