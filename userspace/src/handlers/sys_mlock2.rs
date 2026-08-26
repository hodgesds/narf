#[allow(unused_imports)]
use super::*;

/// `mlock2(addr, len, flags)` — eager mlock with flags=0, or mark pages to
/// become locked when faulted with MLOCK_ONFAULT.
///
/// `mm/mlock.c::SYSCALL_DEFINE3(mlock2)`:
///
/// ```text
///     if (flags & ~MLOCK_ONFAULT) return -EINVAL;
///     ...
///     return do_mlock(start, len, vm_flags);
/// ```
///
/// `flags` is an `int`, so only the low 32 bits are the caller's request, and
/// the unknown-bit EINVAL is decided before `do_mlock`'s EPERM. Everything
/// after that is `do_mlock`, so the same alignment rounding and the same
/// EPERM/ENOMEM/EAGAIN split as `mlock(2)` applies — see
/// [`super::handler_sys_mlock::mlock_align_range`] for why a misaligned
/// `addr` must not be an error.
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
    let (start, len) = match super::handler_sys_mlock::mlock_align_range(a.arg0, a.arg1) {
        Ok(Some(range)) => range,
        Ok(None) => {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    let as_ref = match current_address_space() {
        Some(x) => x,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let result = if a.arg2 as u32 & MLOCK_ONFAULT != 0 {
        as_ref.mlock_range_onfault_limited(
            VirtAddr::new(start),
            len,
            authority.limit_bytes,
            authority.bypass_limit,
        )
    } else {
        as_ref.mlock_range_limited(
            VirtAddr::new(start),
            len,
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
