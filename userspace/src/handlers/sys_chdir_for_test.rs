#[allow(unused_imports)]
use super::*;

#[doc(hidden)]
pub fn sys_chdir_for_test(ctx: &mut dyn TrapContext) {
    sys_chdir(ctx);
}
