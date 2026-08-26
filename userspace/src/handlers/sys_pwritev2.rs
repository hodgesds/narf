#[allow(unused_imports)]
use super::*;

/// `pwritev2(fd, iov, iovcnt, pos_l, pos_h, flags)` — positioned vectored
/// write with a flags word. See `sys_preadv2`.
pub(crate) fn sys_pwritev2(ctx: &mut dyn TrapContext) {
    preadv_pwritev(ctx, true, true);
}
