#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_recv(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1;
    // `import_ubuf` clamps an oversized length to MAX_RW_COUNT rather than
    // failing; NARF's staging bound is MAX_USER_COPY.
    let buf_len = core::cmp::min(args.arg2 as usize, MAX_USER_COPY);
    let flags = args.arg3 as u32;
    // Linux __sys_recvfrom imports the destination iterator before fd lookup,
    // so a faulting non-empty buffer wins over EBADF/ENOTSOCK.
    if buf_len > 0 && validate_user_range(buf_ptr, buf_len).is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // SO_RCVTIMEO: pick up this call's deadline if it is re-executing.
    let resumed = sock_timeo_take(ctx, &sock);
    // A recv is non-blocking if the fd is O_NONBLOCK or the call carries
    // MSG_DONTWAIT (0x40). Such a recv must return EAGAIN the instant the ring
    // is empty-but-open — NEVER park. GLib's GSocket does exactly non-blocking
    // recv() + its own poll loop; parking here stalls its dbus auth handshake,
    // and the old "set 0 then yield" path could even surface a spurious 0 (EOF).
    const MSG_DONTWAIT: u32 = 0x40;
    // MSG_ERRQUEUE never waits either: `ip_recv_error` returns EAGAIN at once
    // when the error queue is empty (net/ipv4/ip_sockglue.c:535).
    let nonblock = (flags & (MSG_DONTWAIT | crate::socket::MSG_ERRQUEUE)) != 0
        || fd::with_table(current_task_id(), |t| {
            t.status_flags(fd)
                .map(|flags| flags & crate::fd::O_NONBLOCK != 0)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    // MSG_WAITALL on a blocking kernel-TCP socket waits for the full length
    // (Linux `tcp_recvmsg_locked`: `target = sock_rcvlowat(sk, waitall, len)`).
    const MSG_WAITALL: u32 = 0x100;
    if flags & MSG_WAITALL != 0 && flags & crate::socket::MSG_PEEK == 0 && !nonblock && buf_len > 0
    {
        if let Some(tcb) = sock.kernel_tcb_id() {
            match tcp_recv_waitall(ctx, &sock, tcb, buf_ptr, buf_len, resumed) {
                None => {}
                Some(Ok(n)) => {
                    if args.arg4 != 0 {
                        if let Err(errno) = move_addr_to_user(None, args.arg4, args.arg5) {
                            ctx.set_return(errno_ret(errno));
                            return;
                        }
                    }
                    ctx.set_return(SyscallReturn::ok(n as u64));
                }
                Some(Err(crate::socket::SockError::WouldBlock)) => {
                    socket_recv_would_block(ctx, nonblock, sock.as_ref(), resumed);
                }
                Some(Err(e)) => ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64)),
            }
            return;
        }
    }
    let mut buf = alloc::vec![0u8; buf_len];
    let result = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags,
    });
    let (result, truncated_full_len) = match result {
        crate::socket::SocketOpResult::ReceivedTruncated {
            copied,
            full_len,
            peer,
        } => (
            crate::socket::SocketOpResult::Received { n: copied, peer },
            Some(full_len),
        ),
        other => (other, None),
    };
    match result {
        crate::socket::SocketOpResult::Received { n, peer } => {
            // recv()/recvfrom() cannot return ancillary data. Consume and
            // drop any rights/credentials attached to this record so a later
            // recvmsg cannot steal them from the wrong message.
            drop(sock.unix_take_recv_fds());
            let _ = sock.recvmsg_cred();
            let _ = sock.take_netlink_user_recv_cred();
            let _ = sock.netlink_pktinfo();
            let _ = sock.take_packet_recv_ancillary();
            // Copy received bytes back to user under SMAP bracket.
            // SAFETY: ptr validated above; AS still active.
            // Linux permits recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC) as a
            // datagram-length probe. Do not validate/copy a zero-byte range:
            // a null pointer is valid when no payload bytes are requested.
            if n > 0 && unsafe { copy_to_user(buf_ptr, &buf[..n]) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
            // recvfrom source-address output: arg4 points to sockaddr storage,
            // arg5 points to its in/out socklen_t. Plain recv passes arg4 = 0.
            // `__sys_recvfrom` runs `move_addr_to_user` whenever `addr` is
            // non-NULL, so a NULL/faulting addrlen is -EFAULT and a
            // connection-oriented socket (no source address) reports 0.
            if args.arg4 != 0 {
                if let Err(errno) = move_addr_to_user(peer.as_ref(), args.arg4, args.arg5) {
                    ctx.set_return(errno_ret(errno));
                    return;
                }
            }
            let returned = if flags & crate::socket::MSG_TRUNC != 0 {
                truncated_full_len.unwrap_or(n)
            } else {
                n
            };
            ctx.set_return(SyscallReturn::ok(returned as u64));
        }
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            socket_recv_would_block(ctx, nonblock, sock.as_ref(), resumed);
        }
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(errno_ret(EINVAL)), // unreachable
    }
}


/// An empty receive queue: a non-blocking receive reports -EAGAIN at once; a
/// blocking one parks on the socket's read readiness and RE-EXECUTES the
/// syscall when woken (`sock_recvmsg` sleeps in the protocol's wait loop and
/// never returns a spurious 0, which a caller would read as EOF). The sleep
/// is bounded by SO_RCVTIMEO (`sock_rcvtimeo`).
pub(super) fn socket_recv_would_block(
    ctx: &mut dyn TrapContext,
    nonblock: bool,
    sock: &crate::socket::SocketFile,
    resumed: Option<u64>,
) {
    if nonblock {
        ctx.set_return(errno_ret(EAGAIN));
        return;
    }
    socket_block(
        ctx,
        sock,
        narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
        sock.rcvtimeo(),
        resumed,
    );
}

/// Identity of one blocking socket call across its re-executions: the
/// syscall's return address (unchanged by the RIP rewind) and the socket.
fn sock_timeo_key(ctx: &dyn TrapContext, sock: &crate::socket::SocketFile) -> u64 {
    (ctx.rip() ^ (sock as *const crate::socket::SocketFile as u64).rotate_left(17)) | 1
}

/// Take the persisted SO_RCVTIMEO/SO_SNDTIMEO deadline of a parked socket
/// call. Every socket handler that can block calls this FIRST, so the
/// deadline survives only for as long as the same call keeps re-executing;
/// a call that completes (or a different call) leaves nothing behind.
pub(super) fn sock_timeo_take(ctx: &dyn TrapContext, sock: &crate::socket::SocketFile) -> Option<u64> {
    use core::sync::atomic::Ordering;
    let uctx = crate::user_task::current_user_task()?;
    // SAFETY: the live per-task context of the task executing this syscall;
    // only atomics are touched.
    let uc = unsafe { &*uctx };
    let key = uc.sock_timeo_key.swap(0, Ordering::AcqRel);
    let deadline = uc.sock_timeo_deadline_ns.swap(0, Ordering::AcqRel);
    (key != 0 && key == sock_timeo_key(ctx, sock) && deadline != 0).then_some(deadline)
}

/// A blocking socket operation that cannot make progress. `timeo` is the
/// socket's SO_RCVTIMEO / SO_SNDTIMEO in jiffies (`None` = forever) and
/// `resumed` the deadline carried over from this call's previous
/// execution. Linux's wait loops (`sk_wait_data`, `sock_wait_for_wmem`,
/// `inet_csk_wait_for_connect`, `unix_wait_for_peer`) return -EAGAIN when
/// the timeout runs out and `sock_intr_errno(timeo)` — -EINTR for a finite
/// timeout — when a signal interrupts the wait.
pub(super) fn socket_block(
    ctx: &mut dyn TrapContext,
    sock: &crate::socket::SocketFile,
    interest: u32,
    timeo: Option<u64>,
    resumed: Option<u64>,
) {
    use core::sync::atomic::Ordering;
    let Some(timeo_ns) = crate::socket::timeo_ns(timeo) else {
        if park_reexecute_on_fd(ctx, sock, interest) {
            return;
        }
        // Kernel-test / nested (recvmmsg) context cannot sleep: surface the
        // retryable condition rather than a fabricated EOF.
        ctx.set_return(errno_ret(EAGAIN));
        return;
    };
    let now = narf_scheduler::narf_time::monotonic_ns();
    let deadline = resumed.unwrap_or_else(|| now.saturating_add(timeo_ns));
    if timeo_ns == 0 || now >= deadline {
        ctx.set_return(errno_ret(EAGAIN));
        return;
    }
    if has_interrupting_signal(current_task_id()) {
        ctx.set_return(errno_ret(EINTR));
        return;
    }
    let key = sock_timeo_key(ctx, sock);
    if let Some(uctx) = crate::user_task::current_user_task() {
        // SAFETY: as in `sock_timeo_take`.
        let uc = unsafe { &*uctx };
        uc.sock_timeo_deadline_ns.store(deadline, Ordering::Release);
        uc.sock_timeo_key.store(key, Ordering::Release);
    }
    if park_reexecute_on_fd_until(ctx, sock, interest, deadline) {
        return;
    }
    let _ = sock_timeo_take(ctx, sock);
    ctx.set_return(errno_ret(EAGAIN));
}

/// Bytes the same blocking stream call (same syscall return address and
/// socket) had already moved before it parked; 0 for a fresh call. Taken —
/// a completed call never leaves progress for the next one.
pub(super) fn sock_progress_take(ctx: &dyn TrapContext, sock: &crate::socket::SocketFile) -> usize {
    use core::sync::atomic::Ordering;
    let Some(uctx) = crate::user_task::current_user_task() else {
        return 0;
    };
    // SAFETY: the live per-task context of the task executing this syscall;
    // only atomics are touched.
    let uc = unsafe { &*uctx };
    let key = uc.sock_progress_key.swap(0, Ordering::AcqRel);
    let done = uc.sock_progress_done.swap(0, Ordering::AcqRel);
    if key != 0 && key == sock_timeo_key(ctx, sock) {
        done as usize
    } else {
        0
    }
}

fn sock_progress_store(ctx: &dyn TrapContext, sock: &crate::socket::SocketFile, done: usize) {
    use core::sync::atomic::Ordering;
    if let Some(uctx) = crate::user_task::current_user_task() {
        // SAFETY: as in `sock_progress_take`.
        let uc = unsafe { &*uctx };
        uc.sock_progress_done.store(done as u64, Ordering::Release);
        uc.sock_progress_key.store(sock_timeo_key(ctx, sock), Ordering::Release);
    }
}

/// What a progress-keeping stream wait decided.
pub(super) enum StreamWait {
    /// The task parked; the syscall re-executes when the socket is ready.
    Parked,
    /// Stop here and return the bytes already moved (Linux returns the
    /// partial count when a signal, the SO_{RCV,SND}TIMEO timeout or a
    /// non-sleeping context ends the wait after some progress).
    Return,
}

/// Park a blocking stream call that has already moved `done > 0` bytes until
/// `interest` is ready, keeping `done` (and the SO_*TIMEO deadline) for the
/// re-execution. Linux `sk_stream_wait_memory` / `sk_wait_data` loops return
/// the partial count instead of an error once something was copied.
pub(super) fn stream_wait_with_progress(
    ctx: &mut dyn TrapContext,
    sock: &crate::socket::SocketFile,
    interest: u32,
    timeo: Option<u64>,
    resumed: Option<u64>,
    done: usize,
) -> StreamWait {
    use core::sync::atomic::Ordering;
    if has_interrupting_signal(current_task_id()) {
        return StreamWait::Return;
    }
    let deadline = match crate::socket::timeo_ns(timeo) {
        None => u64::MAX,
        Some(0) => return StreamWait::Return,
        Some(t) => {
            let now = narf_scheduler::narf_time::monotonic_ns();
            let d = resumed.unwrap_or_else(|| now.saturating_add(t));
            if now >= d {
                return StreamWait::Return;
            }
            if let Some(uctx) = crate::user_task::current_user_task() {
                // SAFETY: as in `sock_timeo_take`.
                let uc = unsafe { &*uctx };
                uc.sock_timeo_deadline_ns.store(d, Ordering::Release);
                uc.sock_timeo_key
                    .store(sock_timeo_key(ctx, sock), Ordering::Release);
            }
            d
        }
    };
    sock_progress_store(ctx, sock, done);
    if park_reexecute_on_fd_until(ctx, sock, interest, deadline) {
        return StreamWait::Parked;
    }
    let _ = sock_progress_take(ctx, sock);
    let _ = sock_timeo_take(ctx, sock);
    StreamWait::Return
}

/// Outcome of [`tcp_send_all`].
pub(super) enum SendAll {
    /// Return this byte count (the whole buffer, or a partial count after a
    /// signal / timeout / error that followed some progress).
    Done(usize),
    /// The call parked and re-executes later.
    Parked,
    /// Nothing was sent and the send buffer is full: the caller's ordinary
    /// would-block path (EAGAIN / park / EINTR / timeout) applies.
    WouldBlock,
    /// Nothing was sent: this error (EPIPE raises SIGPIPE at the caller).
    Err(crate::socket::SockError),
}

/// Linux `tcp_sendmsg_locked` on a BLOCKING socket: queue the whole user
/// buffer, sleeping for send-buffer space as often as needed, and return the
/// full length. The send buffer holds far less than a 16 MiB write, so one
/// call spans many park / re-execute rounds; the bytes already queued ride
/// across them in `sock_progress_*`. A signal or SO_SNDTIMEO ends the wait
/// with the partial count, as does an error after some progress
/// (`do_error: if (copied) goto out`).
pub(super) fn tcp_send_all(
    ctx: &mut dyn TrapContext,
    sock: &crate::socket::SocketFile,
    tcb: u32,
    user_ptr: u64,
    len: usize,
    resumed_timeo: Option<u64>,
) -> SendAll {
    const CHUNK: usize = 1 << 20;
    let mut done = sock_progress_take(ctx, sock).min(len);
    while done < len {
        let want = core::cmp::min(CHUNK, len - done);
        // SAFETY: the caller validated the whole user range; the guarded
        // copy still reports a racing unmap.
        let payload = match unsafe { copy_from_user_vec(user_ptr + done as u64, want) } {
            Ok(p) => p,
            Err(_) if done > 0 => return SendAll::Done(done),
            Err(e) => return SendAll::Err(crate::socket::SockError::Stack(e as i32)),
        };
        match narf_net::tcp_stack::send_errno(tcb, &payload) {
            Ok(n) => {
                done += n;
                if n == want {
                    continue;
                }
            }
            Err(e) if e == narf_lib::errno::EAGAIN as i32 => {}
            Err(_) if done > 0 => return SendAll::Done(done),
            Err(e) => return SendAll::Err(crate::socket::SockError::from_stack(e)),
        }
        if done == 0 {
            return SendAll::WouldBlock;
        }
        match stream_wait_with_progress(
            ctx,
            sock,
            narf_filesystem::POLL_OUT | narf_filesystem::POLL_HUP,
            sock.sndtimeo(),
            resumed_timeo,
            done,
        ) {
            StreamWait::Parked => return SendAll::Parked,
            StreamWait::Return => return SendAll::Done(done),
        }
    }
    SendAll::Done(done)
}

/// Linux `tcp_recvmsg_locked` with MSG_WAITALL on a BLOCKING socket: keep
/// reading until `len` bytes arrived, EOF, an error, a signal or the
/// SO_RCVTIMEO timeout; what was copied so far is returned in the last four
/// cases. Bytes go straight to the user buffer, so a re-execution resumes at
/// `user_ptr + done`. `None`: the call parked. `Some(Err(WouldBlock))`:
/// nothing arrived yet and the caller's ordinary would-block path applies.
pub(super) fn tcp_recv_waitall(
    ctx: &mut dyn TrapContext,
    sock: &crate::socket::SocketFile,
    tcb: u32,
    user_ptr: u64,
    len: usize,
    resumed_timeo: Option<u64>,
) -> Option<Result<usize, crate::socket::SockError>> {
    const CHUNK: usize = 1 << 20;
    let mut done = sock_progress_take(ctx, sock).min(len);
    let mut buf = alloc::vec![0u8; core::cmp::min(CHUNK, len.saturating_sub(done)).max(1)];
    while done < len {
        let want = core::cmp::min(buf.len(), len - done);
        match narf_net::tcp_stack::recv_errno(tcb, &mut buf[..want]) {
            Ok(0) => return Some(Ok(done)),
            Ok(n) => {
                // SAFETY: the caller validated the whole user range; the
                // guarded copy reports a racing unmap.
                if unsafe { copy_to_user(user_ptr + done as u64, &buf[..n]) }.is_err() {
                    return Some(if done > 0 {
                        Ok(done)
                    } else {
                        Err(crate::socket::SockError::Stack(EFAULT as i32))
                    });
                }
                done += n;
                continue;
            }
            Err(e) if e == narf_lib::errno::EAGAIN as i32 => {}
            Err(_) if done > 0 => return Some(Ok(done)),
            Err(e) => return Some(Err(crate::socket::SockError::from_stack(e))),
        }
        if done == 0 {
            return Some(Err(crate::socket::SockError::WouldBlock));
        }
        match stream_wait_with_progress(
            ctx,
            sock,
            narf_filesystem::POLL_IN | narf_filesystem::POLL_HUP,
            sock.rcvtimeo(),
            resumed_timeo,
            done,
        ) {
            StreamWait::Parked => return None,
            StreamWait::Return => return Some(Ok(done)),
        }
    }
    Some(Ok(done))
}
