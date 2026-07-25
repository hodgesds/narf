#[allow(unused_imports)]
use super::*;

/// `set_mempolicy(mode, nodemask, maxnode)`.
pub(crate) fn sys_set_mempolicy(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let mode = a.arg0 as u32;
    if !mpol_mode_valid(mode) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let nodemask = if a.arg1 != 0 {
        read_user_u64(a.arg1)
    } else {
        0
    };
    let task = current_task_id();
    let mut g = MEMPOLICY_TABLE.lock();
    g.get_or_insert_with(alloc::collections::BTreeMap::new)
        .insert(task, (mode, nodemask));
    ctx.set_return(SyscallReturn::ok(0));
}
