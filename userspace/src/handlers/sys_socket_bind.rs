#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_bind(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let addr_len = args.arg2;
    // Linux __sys_bind: sockfd_lookup_light gives -EBADF / -ENOTSOCK, then
    // move_addr_to_kernel gives -EINVAL / -EFAULT, then the family's bind op.
    let sock = match current_socket_result(fd) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    let addr = match copy_user_addr_result(addr_ptr, addr_len) {
        Ok(a) => a,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
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
        // EADDRINUSE / EADDRNOTAVAIL / EINVAL / EACCES / EAFNOSUPPORT from the
        // family's bind op, rather than a bare -1/EPERM.
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // -EINVAL (unreachable)
    }
}
