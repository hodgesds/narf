#[allow(unused_imports)]
use super::*;

/// `getpeername(fd, addr_out, addrlen_inout)`.
pub(crate) fn sys_socket_getpeername(ctx: &mut dyn TrapContext) {
    sys_socket_get_addr(ctx, true);
}
