#[allow(unused_imports)]
use super::*;

/// `sendmmsg(fd, mmsghdr*, vlen, flags)` — send up to `vlen` messages,
/// writing each message's transmitted byte count into its `msg_len`.
/// Stops at the first failing message; returns the count sent.
pub(crate) fn sys_socket_sendmmsg(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let fd = a.arg0;
    let mmsg_ptr = a.arg1;
    let vlen = a.arg2 as usize;
    let flags = a.arg3;
    let mut sent = 0usize;
    let mut would_block = false;
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
        sys_socket_sendmsg(&mut cap);
        if (cap.ret_value as i64) < 0 {
            would_block = cap.ret_value as i64 == -(EAGAIN_CODE as i64);
            break;
        }
        write_user_u32(hdr_ptr + MMSGHDR_MSGLEN_OFF, cap.ret_value as u32);
        sent += 1;
    }
    if sent == 0 && would_block {
        if let Some(sock) = current_socket(fd as u32) {
            handler_sys_socket_send::socket_send_would_block(
                ctx,
                fd as u32,
                flags as u32,
                sock.as_ref(),
            );
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(sent as u64));
}
