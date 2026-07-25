#[allow(unused_imports)]
use super::*;

/// `shmdt(shmaddr)` — detach (unmap) a previously-attached segment.
#[cfg(feature = "linux-compat")]
pub(crate) fn sys_shmdt(ctx: &mut dyn TrapContext) {
    let addr = ctx.args().arg0;
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match as_ref.unmap_region(VirtAddr::new(addr)) {
        Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // EINVAL
    }
}
