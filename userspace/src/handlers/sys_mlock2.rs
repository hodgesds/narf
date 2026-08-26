#[allow(unused_imports)]
use super::*;

/// `mlock2(addr, len, flags)` — eager mlock with flags=0, or mark pages to
/// become locked when faulted with MLOCK_ONFAULT.
pub(crate) fn sys_mlock2(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    const MLOCK_ONFAULT: u32 = 1;
    if a.arg2 as u32 & !MLOCK_ONFAULT != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let authority = current_mlock_authority();
    if !can_do_mlock(authority) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }
    let as_ref = match current_address_space() {
        Some(x) => x,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let result = if a.arg2 as u32 & MLOCK_ONFAULT != 0 {
        as_ref.mlock_range_onfault_limited(
            VirtAddr::new(a.arg0),
            a.arg1,
            authority.limit_bytes,
            authority.bypass_limit,
        )
    } else {
        as_ref.mlock_range_limited(
            VirtAddr::new(a.arg0),
            a.arg1,
            authority.limit_bytes,
            authority.bypass_limit,
        )
    };
    match result {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(error) => ctx.set_return(SyscallReturn::ok(
            (-super::handler_sys_mlock::mlock_errno(error)) as u64,
        )),
    }
}
