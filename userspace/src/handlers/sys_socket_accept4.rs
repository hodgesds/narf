#[allow(unused_imports)]
use super::*;

/// `accept4(2)` — accept(2) plus SOCK_CLOEXEC / SOCK_NONBLOCK on the
/// returned fd. arg3 carries the flags.
pub(crate) fn sys_socket_accept4(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg3 as u32;
    accept_common(ctx, flags);
}
