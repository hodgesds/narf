#[allow(unused_imports)]
use super::*;

/// `mlockall(flags)` — lock the whole address space. MCL_CURRENT pins every
/// existing region, eagerly unless MCL_ONFAULT is present. MCL_FUTURE is
/// accepted but future-VMA policy is not retained yet.
pub(crate) fn sys_mlockall(ctx: &mut dyn TrapContext) {
    const MCL_CURRENT: u64 = 1;
    const MCL_FUTURE: u64 = 2;
    const MCL_ONFAULT: u64 = 4;
    let flags = ctx.args().arg0;
    if flags == 0
        || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0
        || flags & MCL_ONFAULT != 0 && flags & (MCL_CURRENT | MCL_FUTURE) == 0
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    if flags & MCL_CURRENT != 0 {
        for r in as_ref.regions_snapshot() {
            let result = if flags & MCL_ONFAULT != 0 {
                as_ref.mlock_range_onfault(r.base, r.len)
            } else {
                as_ref.mlock_range(r.base, r.len)
            };
            if result.is_err() {
                ctx.set_return(SyscallReturn::invalid_op());
                return;
            }
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}
