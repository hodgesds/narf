#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_process_vm_writev(ctx: &mut dyn TrapContext) {
    process_vm_transfer(ctx, true);
}
