#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_shutdown(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let how = args.arg1 as u32;
    // Linux __sys_shutdown: sockfd_lookup_light gives -EBADF / -ENOTSOCK, then
    // the family's shutdown op (-ENOTCONN, or -EINVAL for a bad `how`).
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Shutdown { how }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // -EINVAL (unreachable)
    }
}
