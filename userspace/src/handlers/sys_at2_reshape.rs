#[allow(unused_imports)]
use super::*;

/// `fchmodat2(dirfd, path, mode, flags)` has the same first three arguments
/// as `fchmodat`; the fourth argument is accepted by the chmod handler.
pub(crate) fn sys_at2_reshape(ctx: &mut dyn TrapContext) {
    sys_fchmodat2(ctx);
}
