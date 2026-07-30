#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_bind(ctx: &mut dyn TrapContext) {
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
    // A pathname AF_UNIX bind materialises a real S_IFSOCK inode in Linux.
    // Grab the path before the op consumes `addr` (family is checked in the
    // op; AF_UNIX bodies are the sun_path bytes).
    let unix_path: Option<alloc::string::String> = if addr.family == crate::socket::AF_UNIX {
        core::str::from_utf8(&addr.body)
            .ok()
            .map(|s| alloc::string::String::from(s.trim_end_matches('\0')))
    } else {
        None
    };
    // `unix_bind_bsd()` creates the S_IFSOCK dentry before publishing the
    // socket.  The registry key is consequently the inode identity from the
    // outset, which lets a later file bind find the same endpoint through a
    // different mount parent.
    if let Some(p) = unix_path.as_deref() {
        create_unix_socket_node(p);
    }
    match sock.dispatch_op(crate::socket::SocketOp::Bind { addr }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        _ => ctx.set_return(fail),
    }
}
