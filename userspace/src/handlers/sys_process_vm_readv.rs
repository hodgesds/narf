#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_process_vm_readv(ctx: &mut dyn TrapContext) {
    process_vm_transfer(ctx, false);
}
