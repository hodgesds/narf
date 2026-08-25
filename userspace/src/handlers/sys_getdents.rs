#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getdents(ctx: &mut dyn TrapContext) {
    super::handler_sys_getdents64::sys_getdents_common(ctx, true);
}
