#[allow(unused_imports)]
use super::*;

/// `set_robust_list(head, len)` — register the calling thread's robust
/// futex list head.
pub(crate) fn sys_set_robust_list(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let mut g = ROBUST_LIST_TABLE.lock();
    let m = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    m.insert(task, (a.arg0, a.arg1));
    ctx.set_return(SyscallReturn::ok(0));
}
