#[allow(unused_imports)]
use super::*;

/// `mlock2(addr, len, flags)` — like mlock with the MLOCK_ONFAULT
/// flag. NARF force-backs the range either way, so the flag is
/// accepted but doesn't change behaviour.
pub(crate) fn sys_mlock2(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    const MLOCK_ONFAULT: u32 = 1;
    if a.arg2 as u32 & !MLOCK_ONFAULT != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let as_ref = match current_address_space() {
        Some(x) => x,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    match as_ref.mlock_range(VirtAddr::new(a.arg0), a.arg1) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}
