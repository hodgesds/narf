#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_listen(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let backlog = args.arg1 as u32;
    // Linux __sys_listen: sockfd_lookup_light gives -EBADF / -ENOTSOCK, then
    // the family's listen op (-EADDRINUSE / -EOPNOTSUPP for a non-stream sock).
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Listen { backlog }) {
        crate::socket::SocketOpResult::Ok(_) => {
            // The starved-accept sweep compares this against the acceptor's
            // recorded poll fd set. `dispatch_op` cannot capture it — only
            // this layer knows which fd the listener is.
            #[cfg(feature = "unix-latency-trace")]
            sock.set_listen_owner_fd(fd);
            ctx.set_return(SyscallReturn::ok(0))
        }
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // -EINVAL (unreachable)
    }
}
