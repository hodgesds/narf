#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_connect(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let addr_len = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let addr = match copy_user_addr(addr_ptr, addr_len) {
        Some(a) => a,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Connect { addr }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(fail),
    }
}
