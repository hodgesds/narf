#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sock_send_zc(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_id = args.arg1 as u32;
    let off = args.arg2;
    let len = args.arg3;
    let _flags = args.arg4 as u32;
    // Per-branch errnos (the old bare -1 sentinel reached libc as EPERM for
    // every failure). Modelled on sendmsg(2): a bad/unknown registered buffer
    // or out-of-range slice is -EFAULT (bad send buffer), a bad fd is -EBADF,
    // a non-socket fd is -ENOTSOCK, and a send failure carries the socket's
    // own errno.
    let task = current_task_id();
    let (vaddr, slice_len) = match crate::socket::registered_buffer_slice(task, buf_id, off, len) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
    };
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    // "Zero-copy" in the NARF sense: copy once under SMAP bracket into
    // a kernel staging buffer, then hand to the socket dispatcher.
    // A real NIC TX path will map this as a DMA descriptor instead —
    // that upgrade lands when the NIC driver does; for now the
    // AF_UNIX/loopback path requires a kernel-owned buffer.
    let n_bytes = slice_len as usize;
    let mut kbuf = alloc::vec![0u8; n_bytes];
    // SAFETY: vaddr is a pinned user VA from a registered buffer.
    if unsafe { copy_from_user(&mut kbuf, vaddr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    match sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: &kbuf,
        flags: 0,
        addr: None,
    }) {
        crate::socket::SocketOpResult::Ok(n) => ctx.set_return(SyscallReturn::ok(n)),
        // Propagate the socket's real send errno (EPIPE, ECONNRESET, ENOTCONN,
        // EAGAIN, …) instead of a blanket -1/EPERM.
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64))
        }
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // -EINVAL (no other variant expected for Send)
    }
}
