#[allow(unused_imports)]
use super::*;

#[doc(hidden)]
pub fn sys_chroot_for_test(ctx: &mut dyn TrapContext) {
    sys_chroot(ctx);
}
