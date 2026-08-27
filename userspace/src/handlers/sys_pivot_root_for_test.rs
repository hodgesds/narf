#[allow(unused_imports)]
use super::*;

#[cfg(feature = "container")]
#[doc(hidden)]
pub fn sys_pivot_root_for_test(ctx: &mut dyn TrapContext) {
    sys_pivot_root(ctx);
}
