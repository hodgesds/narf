#[allow(unused_imports)]
use super::*;

/// `pkey_alloc(flags, access_rights)` — allocate the lowest free key.
pub(crate) fn sys_pkey_alloc(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    // Linux defines no flags; any non-zero value is EINVAL.
    if a.arg0 != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let task = current_task_id();
    let mut g = PKEY_TABLE.lock();
    let m = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    let bits = m.entry(task).or_insert(0);
    for k in 1..16u32 {
        if *bits & (1 << k) == 0 {
            *bits |= 1 << k;
            ctx.set_return(SyscallReturn::ok(k as u64));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok((-28i64) as u64)); // ENOSPC
}
