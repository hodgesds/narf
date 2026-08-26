#[allow(unused_imports)]
use super::*;

/// `preadv2(fd, iov, iovcnt, pos_l, pos_h, flags)` — positioned vectored
/// read with a flags word. On LP64 `pos_h` is zero and the offset is
/// `pos_l` (arg3), so the core matches `preadv`; the RWF_* flags (arg5)
/// are accepted but not specially honoured.
pub(crate) fn sys_preadv2(ctx: &mut dyn TrapContext) {
    preadv_pwritev(ctx, false, true);
}
