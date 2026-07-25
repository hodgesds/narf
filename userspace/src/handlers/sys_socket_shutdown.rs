#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_shutdown(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let how = args.arg1 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Shutdown { how }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}
