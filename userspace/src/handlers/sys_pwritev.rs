#[allow(unused_imports)]
use super::*;

/// `pwritev(fd, iov, iovcnt, offset)` — positioned vectored write.
pub(crate) fn sys_pwritev(ctx: &mut dyn TrapContext) {
    preadv_pwritev(ctx, true);
}
