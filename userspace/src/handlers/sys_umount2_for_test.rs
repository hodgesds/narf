#[allow(unused_imports)]
use super::*;

#[doc(hidden)]
pub fn sys_umount2_for_test(ctx: &mut dyn TrapContext) {
    sys_umount2(ctx);
}
