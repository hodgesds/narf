#[allow(unused_imports)]
use super::*;

/// `munlockall()` — clear the LOCKED flag on every region.
pub(crate) fn sys_munlockall(ctx: &mut dyn TrapContext) {
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    for r in as_ref.regions_snapshot() {
        let _ = as_ref.munlock_range(r.base, r.len);
    }
    ctx.set_return(SyscallReturn::ok(0));
}
