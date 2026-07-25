#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_accept(ctx: &mut dyn TrapContext) {
    accept_common(ctx, 0);
}
