#[allow(unused_imports)]
use super::*;

const MSG_CMSG_COMPAT: u32 = 0x8000_0000;
const UIO_MAXIOV: usize = 1024;

/// `sendmmsg(fd, mmsghdr*, vlen, flags)` — preserve the first error when no
/// datagram was sent, and suppress a later error only after a committed prefix.
pub(crate) fn sys_socket_sendmmsg(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let mmsg_ptr = args.arg1;
    let vlen = core::cmp::min(args.arg2 as u32 as usize, UIO_MAXIOV);
    let flags = args.arg3 as u32;

    // Linux performs both checks before touching the message vector, including
    // when vlen is zero.
    if flags & MSG_CMSG_COMPAT != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let sock = match current_socket_result(fd) {
        Ok(socket) => socket,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };

    let mut sent = 0usize;
    let mut first_error = 0i64;
    for i in 0..vlen {
        let Some(hdr_ptr) = (i as u64)
            .checked_mul(MMSGHDR_SZ)
            .and_then(|offset| mmsg_ptr.checked_add(offset))
        else {
            first_error = 14; // EFAULT
            break;
        };
        match handler_sys_socket_sendmsg::sendmsg_on_socket(&sock, hdr_ptr, flags, true) {
            handler_sys_socket_sendmsg::SendMsgResult::Sent { written, complete } => {
                // Linux increments the completed-message count only after the
                // msg_len store succeeds. The payload may already be visible if
                // this write faults; the syscall nevertheless reports EFAULT
                // when it was the first entry.
                // SAFETY: `copy_to_user` validates the four-byte destination and
                // uses the architecture's guarded user-access path.
                if unsafe {
                    copy_to_user(
                        hdr_ptr + MMSGHDR_MSGLEN_OFF,
                        &(written as u32).to_ne_bytes(),
                    )
                }
                .is_err()
                {
                    first_error = 14;
                    break;
                }
                sent += 1;
                if !complete {
                    break;
                }
            }
            handler_sys_socket_sendmsg::SendMsgResult::WouldBlock => {
                first_error = EAGAIN_CODE as i64;
                break;
            }
            handler_sys_socket_sendmsg::SendMsgResult::Error(errno) => {
                first_error = errno;
                break;
            }
        }
    }

    if sent != 0 {
        ctx.set_return(SyscallReturn::ok(sent as u64));
        return;
    }
    if first_error == EAGAIN_CODE as i64 {
        handler_sys_socket_send::socket_send_would_block(ctx, fd, flags, sock.as_ref());
        return;
    }
    if first_error != 0 {
        ctx.set_return(SyscallReturn::ok((-first_error) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
