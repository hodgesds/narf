#[allow(unused_imports)]
use super::*;

/// `preadv(fd, iov, iovcnt, offset)` — positioned vectored read.
pub(crate) fn sys_preadv(ctx: &mut dyn TrapContext) {
    preadv_pwritev(ctx, false, false);
}
