#[allow(unused_imports)]
use super::*;

/// `recvmmsg(fd, mmsghdr*, vlen, flags, timeout)` — receive up to
/// `vlen` messages, writing each received length into its `msg_len`.
/// Stops when a recv would block; returns the count received.
pub(crate) fn sys_socket_recvmmsg(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let fd = a.arg0;
    let mmsg_ptr = a.arg1;
    let vlen = a.arg2 as usize;
    let flags = a.arg3;
    let mut recvd = 0usize;
    for i in 0..vlen {
        let hdr_ptr = mmsg_ptr + (i as u64) * MMSGHDR_SZ;
        let mut cap = CaptureCtx {
            inner: ctx,
            args: SyscallArgs {
                arg0: fd,
                arg1: hdr_ptr,
                arg2: flags,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            ret_value: 0,
        };
        sys_socket_recvmsg(&mut cap);
        if (cap.ret_value as i64) < 0 {
            break; // would block — no more messages ready
        }
        write_user_u32(hdr_ptr + MMSGHDR_MSGLEN_OFF, cap.ret_value as u32);
        recvd += 1;
    }
    ctx.set_return(SyscallReturn::ok(recvd as u64));
}
