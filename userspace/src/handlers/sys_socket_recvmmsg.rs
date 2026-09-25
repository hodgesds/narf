#[allow(unused_imports)]
use super::*;

/// `recvmmsg(fd, mmsghdr*, vlen, flags, timeout)` — receive up to
/// `vlen` messages, writing each received length into its `msg_len`.
///
/// Mirrors `net/socket.c::do_recvmmsg`:
///   - `sockfd_lookup_light` first → -EBADF / -ENOTSOCK (even for vlen 0);
///   - a faulting timeout → -EFAULT, an invalid one → -EINVAL;
///   - `vlen` is clamped to UIO_MAXIOV;
///   - an error on the FIRST message is returned as-is; once any datagram
///     was received the count is returned instead.
///
/// A blocking socket waits for the first message (the timeout, as in Linux,
/// does not bound that wait); later messages are taken only while ready.
pub(crate) fn sys_socket_recvmmsg(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let fd = a.arg0;
    let mmsg_ptr = a.arg1;
    let flags = a.arg3;
    let timeout_ptr = a.arg4;
    let sock = match current_socket_result(fd as u32) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if timeout_ptr != 0 {
        let mut ts = [0u8; 16];
        // SAFETY: copy_from_user range-validates the timespec and
        // SMAP-brackets the read.
        if unsafe { copy_from_user(&mut ts, timeout_ptr) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let sec = i64::from_ne_bytes(ts[0..8].try_into().unwrap());
        let nsec = i64::from_ne_bytes(ts[8..16].try_into().unwrap());
        // `poll_select_set_timeout` → `timespec64_valid`.
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
    }
    const UIO_MAXIOV: usize = 1024;
    let vlen = core::cmp::min(a.arg2 as u32 as usize, UIO_MAXIOV);
    let mut recvd = 0usize;
    let mut first_err: Option<u64> = None;
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
            first_err = Some(cap.ret_value);
            break;
        }
        // `put_user(err, &entry->msg_len)`: a fault ends the batch.
        // SAFETY: copy_to_user range-validates and SMAP-brackets the write.
        if unsafe {
            copy_to_user(
                hdr_ptr + MMSGHDR_MSGLEN_OFF,
                &(cap.ret_value as u32).to_ne_bytes(),
            )
        }
        .is_err()
        {
            first_err = Some((-EFAULT) as u64);
            break;
        }
        recvd += 1;
    }
    if recvd > 0 {
        ctx.set_return(SyscallReturn::ok(recvd as u64));
        return;
    }
    match first_err {
        Some(ret) if ret as i64 == -EAGAIN => {
            // The nested recvmsg cannot park (its proxy context has no RIP to
            // rewind). A blocking socket with nothing queued sleeps here, on
            // the real context, and re-executes the whole batch when woken.
            const MSG_DONTWAIT: u32 = 0x40;
            let nonblock = (flags as u32 & (MSG_DONTWAIT | crate::socket::MSG_ERRQUEUE)) != 0
                || socket_listener_nonblock(current_task_id(), fd as u32, sock.as_ref());
            handler_sys_socket_recv::socket_recv_would_block(ctx, nonblock, sock.as_ref());
        }
        Some(ret) => ctx.set_return(SyscallReturn::ok(ret)),
        None => ctx.set_return(SyscallReturn::ok(0)),
    }
}
