#[allow(unused_imports)]
use super::*;

/// `pkey_free(pkey)`.
pub(crate) fn sys_pkey_free(ctx: &mut dyn TrapContext) {
    let key = ctx.args().arg0;
    if key == 0 || key >= 16 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let task = current_task_id();
    let mut g = PKEY_TABLE.lock();
    let allocated = g
        .as_mut()
        .and_then(|m| m.get_mut(&task))
        .map(|bits| {
            if *bits & (1 << key) != 0 {
                *bits &= !(1u16 << key);
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    if allocated {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
    }
}
