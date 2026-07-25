#[allow(unused_imports)]
use super::*;

/// `setsockopt(fd, level, optname, opt_val, opt_len)`.
/// Linux ref: net/socket.c:SYSCALL_DEFINE5(setsockopt, ...).
pub(crate) fn sys_socket_setsockopt(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let level = args.arg1 as u32;
    let name = args.arg2 as u32;
    let val_ptr = args.arg3;
    let val_len = args.arg4 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if val_ptr == 0 || val_len == 0 || val_len > 256 {
        ctx.set_return(fail);
        return;
    }
    let mut buf = alloc::vec![0u8; val_len];
    // SAFETY: AS active; SMAP bracket inside copy_from_user.
    if unsafe { copy_from_user(&mut buf, val_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    match sock.dispatch_op(crate::socket::SocketOp::SetSockOpt {
        level,
        name,
        value: &buf,
    }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}
