#[allow(unused_imports)]
use super::*;

/// Linux futex2 `futex_wait(uaddr, val, mask, flags, timeout, clockid)`
/// (x86_64=455, aarch64=455). The futex2 split of the classic FUTEX_WAIT
/// op: same wait word, value-checked, but carries an explicit `mask` and
/// a `flags` word selecting the access size (FUTEX2_SIZE_U32, the only
/// width NARF parks on). `timeout` is an absolute `timespec*`; the
/// cooperative park is bounded (see `FUTEX2_PARK_CAP_NS`), so we don't
/// decode it precisely.
pub(crate) fn sys_futex_wait(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    futex_wait_core(
        ctx,
        futex_namespace((args.arg3 & FUTEX_PRIVATE) != 0),
        args.arg0,
        args.arg1 as u32,
        FUTEX2_PARK_CAP_NS,
    );
}
