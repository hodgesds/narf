#[allow(unused_imports)]
use super::*;

#[doc(hidden)]
pub fn sys_mount_for_test(ctx: &mut dyn TrapContext) {
    sys_mount(ctx);
}
