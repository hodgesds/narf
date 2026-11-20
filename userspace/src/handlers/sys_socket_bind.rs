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
            ctx.set_return(errno_ret(errno));
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
    // `unix_bind_bsd()` creates the S_IFSOCK dentry before publishing the
    // socket.  The registry key is consequently the inode identity from the
    // outset, which lets a later file bind find the same endpoint through a
    // different mount parent.
    //
    // Its `vfs_mknod` runs BEFORE the already-bound test, and an existing
    // name fails it with EEXIST, which `unix_bind_bsd` reports as
    // EADDRINUSE — so a path that exists (a stale socket node, a regular
    // file, …) is EADDRINUSE even for an already-bound socket, while a fresh
    // path on an already-bound socket falls through to the op's EINVAL (and
    // must not leave a node behind).
    // `unix_validate_addr` (an over-long sun_path is EINVAL) runs before the
    // mknod, so only a well-formed address may create a node.
    if addr.family == crate::socket::AF_UNIX && sock.domain == crate::socket::AF_UNIX {
        if let Some(crate::socket::UnixAddr::Path(path)) =
            crate::socket::UnixAddr::parse(&addr.body)
        {
            if crate::handlers::unix_path_final_node_exists(&path) {
                ctx.set_return(errno_ret(EADDRINUSE));
                return;
            }
            if sock.is_fresh() {
                create_unix_socket_node(&path);
            }
        }
    }
    match sock.dispatch_op(crate::socket::SocketOp::Bind { addr }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        // EADDRINUSE / EADDRNOTAVAIL / EINVAL / EACCES / EAFNOSUPPORT from the
        // family's bind op, rather than a bare -1/EPERM.
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(errno_ret(EINVAL)), // unreachable
    }
}
