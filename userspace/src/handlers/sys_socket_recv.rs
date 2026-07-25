#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_recv(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let buf_ptr = args.arg1;
    let buf_len = args.arg2 as usize;
    let flags = args.arg3 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Validate destination range before issuing the Recv op.
    if buf_len > 0 && validate_user_range(buf_ptr, buf_len).is_err() {
        ctx.set_return(fail);
        return;
    }
    // A recv is non-blocking if the fd is O_NONBLOCK or the call carries
    // MSG_DONTWAIT (0x40). Such a recv must return EAGAIN the instant the ring
    // is empty-but-open — NEVER park. GLib's GSocket does exactly non-blocking
    // recv() + its own poll loop; parking here stalls its dbus auth handshake,
    // and the old "set 0 then yield" path could even surface a spurious 0 (EOF).
    const MSG_DONTWAIT: u32 = 0x40;
    let nonblock = (flags & MSG_DONTWAIT) != 0
        || fd::with_table(current_task_id(), |t| {
            t.get(fd)
                .map(|e| e.status_flags & crate::fd::O_NONBLOCK != 0)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let mut buf = alloc::vec![0u8; buf_len];
    let result = sock.dispatch_op(crate::socket::SocketOp::Recv {
        buf: &mut buf,
        flags,
    });
    match result {
        crate::socket::SocketOpResult::Received { n, .. } => {
            // Copy received bytes back to user under SMAP bracket.
            // SAFETY: ptr validated above; AS still active.
            if unsafe { copy_to_user(buf_ptr, &buf[..n]) }.is_err() {
                ctx.set_return(fail);
                return;
            }
            ctx.set_return(SyscallReturn::ok(n as u64));
        }
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) if nonblock => {
            ctx.set_return(SyscallReturn::ok((-(EAGAIN_CODE as i64)) as u64));
        }
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            // Yield ~1ms; libc loops.
            if let (Some(uctx), Some(hook)) = (
                crate::user_task::current_user_task(),
                crate::user_task::yield_hook(),
            ) {
                ctx.set_return(SyscallReturn::ok(0));
                let deadline = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
                // SAFETY: `uctx` is the live per-task UserTaskCtx from current_user_task();
                // we hold the only reference while setting the deadline and saving CPU state
                // into `uc.state` before the yield hook hands the task to the executor.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    let uc = &*uctx;
                    uc.sleep_deadline_ns.store(deadline, Ordering::Release);
                    // Park on NET-I/O READINESS (the TCP stack `readiness::notify`s
                    // the listener when a connection becomes accept-ready, and a
                    // socket when data arrives) with the ~1ms deadline as a mere
                    // backstop. Without net_io_wait the park only re-polled every
                    // ~1ms off the timer wheel — and under own-stack cooperative
                    // scheduling with other busy tasks (redis bg threads) that
                    // wheel service is delayed enough that the connection/data
                    // sits ACK'd-but-unread past the client's deadline (net-smoke
                    // echo flake). Snapshot the readiness generation for the
                    // check→park lost-wake guard (park_should_block re-executes if
                    // it moved). Clear a stale `futex_uaddr` so this can't be
                    // mis-routed into the futex branch.
                    uc.futex_uaddr.store(0, Ordering::Release);
                    uc.net_io_wait.store(true, Ordering::Release);
                    uc.epoll_park_gen
                        .store(narf_net::readiness::generation(), Ordering::Release);
                    ctx.save_user_state(uc.state.get() as *mut u8);
                    *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                    if narf_scheduler::stackful::user_own_stack_enabled() {
                        own_stack_block(ctx);
                        return;
                    }
                    hook(uctx);
                }
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => ctx.set_return(fail),
    }
}
