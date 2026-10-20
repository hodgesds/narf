#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_connect(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let addr_len = args.arg2;
    // Linux __sys_connect: fdget gives -EBADF, then move_addr_to_kernel gives
    // -EINVAL / -EFAULT, then __sys_connect_file checks sock_from_file (-ENOTSOCK),
    // and finally the family's connect op (-ECONNREFUSED / -EINPROGRESS / …).
    let task = current_task_id();
    let ops = match fd::with_table(task, |table| table.get(fd).map(|e| e.ops.clone())).flatten() {
        Some(ops) => ops,
        None => {
            ctx.set_return(errno_ret(EBADF));
            return;
        }
    };
    let addr = match copy_user_addr_result(addr_ptr, addr_len) {
        Ok(a) => a,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let sock = match socket_from_file_ops(ops) {
        Some(s) => s,
        None => {
            ctx.set_return(errno_ret(ENOTSOCK));
            return;
        }
    };
    // A blocking connect parked on the handshake re-executes this syscall;
    // pick up its SO_SNDTIMEO deadline.
    let resumed = super::handler_sys_socket_recv::sock_timeo_take(ctx, &sock);
    match sock.dispatch_op(crate::socket::SocketOp::Connect { addr }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        crate::socket::SocketOpResult::Err(e) => {
            let errno = e.errno() as i64;
            let waitable = errno == EINPROGRESS || errno == EALREADY;
            if waitable && sock.inet_connect_pending() && !socket_listener_nonblock(task, fd, &sock) {
                inet_wait_for_connect(ctx, &sock, errno, resumed);
                return;
            }
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
        }
        _ => ctx.set_return(errno_ret(EINVAL)), // unreachable
    }
}

/// `inet_wait_for_connect`: a blocking connect(2) sleeps until the handshake
/// ends — readiness (POLLOUT once established, ERR/HUP once it fails) wakes
/// it and the syscall re-executes, finding the outcome in the SS_CONNECTING
/// switch (`inet_connect_progress`). Bounded by SO_SNDTIMEO: on timeout it
/// returns the state-switch err (EINPROGRESS for the call that started the
/// connect, EALREADY for one that joined it); a signal ends a finite wait
/// with EINTR (`sock_intr_errno`). Nothing spins: the CPU idles while the SYN
/// timer and RX do the work.
fn inet_wait_for_connect(
    ctx: &mut dyn TrapContext,
    sock: &crate::socket::SocketFile,
    errno: i64,
    resumed: Option<u64>,
) {
    use core::sync::atomic::Ordering;
    if resumed.is_none() {
        sock.connect_timeo_errno().store(errno as i32, Ordering::Release);
    }
    let timeout_errno = match sock.connect_timeo_errno().load(Ordering::Acquire) {
        0 => errno,
        e => e as i64,
    };
    if !can_park_reexecute() {
        // Kernel-test / nested context: no task to park. Wait in place.
        let syn_retries = sock.tcp_syncnt();
        let ret = match sock.kernel_tcb_id() {
            Some(id) => {
                let options = narf_net::tcp_stack::ConnectOptions { syn_retries };
                let _ = narf_net::tcp_stack::connect_wait(id, options);
                match sock.inet_connect_progress() {
                    Some(crate::socket::SocketOpResult::Ok(_)) | None => SyscallReturn::ok(0),
                    Some(crate::socket::SocketOpResult::Err(e)) => errno_ret(e.errno() as i64),
                    Some(_) => errno_ret(EINVAL),
                }
            }
            None => errno_ret(timeout_errno),
        };
        ctx.set_return(ret);
        return;
    }
    super::handler_sys_socket_recv::socket_block_with(
        ctx,
        sock,
        narf_filesystem::POLL_OUT | narf_filesystem::POLL_ERR | narf_filesystem::POLL_HUP,
        sock.sndtimeo(),
        resumed,
        timeout_errno,
    );
}
