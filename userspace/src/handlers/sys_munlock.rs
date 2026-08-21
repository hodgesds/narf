#[allow(unused_imports)]
use super::*;

/// `munlock(addr, len)` — clear LOCKED flag (frames stay backed
/// since no swap exists yet to reclaim them). arg0 = base,
/// arg1 = len. Ok(0) on success, InvalidOp if no region
/// is not completely mapped.
pub(crate) fn sys_munlock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match as_ref.munlock_range(VirtAddr::new(args.arg0), args.arg1) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        // Linux munlock(2): EINVAL for an out-of-range request, else ENOMEM for
        // a range that spans an unmapped hole.
        Err(narf_memory::AddressSpaceError::OutOfRange) => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64))
        }
        Err(_) => ctx.set_return(SyscallReturn::ok((-12i64) as u64)),
    }
}
