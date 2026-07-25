#[allow(unused_imports)]
use super::*;

/// `getsockname(fd, addr_out, addrlen_inout)`. Writes the
/// `sockaddr` shape per family. Linux net/socket.c:SYSCALL_DEFINE3.
pub(crate) fn sys_socket_getsockname(ctx: &mut dyn TrapContext) {
    sys_socket_get_addr(ctx, false);
}
