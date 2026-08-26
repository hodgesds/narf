#[allow(unused_imports)]
use super::*;

/// `munlockall()` — clear every current lock and the MCL_FUTURE policy in one
/// address-space transaction.
pub(crate) fn sys_munlockall(ctx: &mut dyn TrapContext) {
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match as_ref.munlock_all() {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(error) => ctx.set_return(SyscallReturn::ok(
            (-super::handler_sys_mlock::mlock_errno(error)) as u64,
        )),
    }
}
