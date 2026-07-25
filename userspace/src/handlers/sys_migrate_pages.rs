#[allow(unused_imports)]
use super::*;

/// `migrate_pages(pid, maxnode, old_nodes, new_nodes)` — migrate the
/// caller's resident private pages between NUMA node sets.
pub(crate) fn sys_migrate_pages(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let task = current_task_id();
    let visible_pid = task_to_pid_raw(task).unwrap_or(task);
    if a.arg0 != 0 && a.arg0 != task && a.arg0 != visible_pid {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
        return;
    }
    if a.arg1 == 0 || a.arg1 > 64 || a.arg2 == 0 || a.arg3 == 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let mut old_bytes = [0u8; 8];
    let mut new_bytes = [0u8; 8];
    // SAFETY: copy_from_user validates the old-nodemask word.
    let old_ok = unsafe { copy_from_user(&mut old_bytes, a.arg2) }.is_ok();
    // SAFETY: copy_from_user validates the new-nodemask word.
    let new_ok = unsafe { copy_from_user(&mut new_bytes, a.arg3) }.is_ok();
    if !old_ok || !new_ok {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let old_nodes = u64::from_ne_bytes(old_bytes);
    let new_nodes = u64::from_ne_bytes(new_bytes);
    let online = numa_node_count().min(64);
    let online_mask = if online == 64 {
        u64::MAX
    } else {
        (1u64 << online) - 1
    };
    let maxnode_mask = if a.arg1 == 64 {
        u64::MAX
    } else {
        (1u64 << a.arg1) - 1
    };
    if old_nodes == 0
        || new_nodes == 0
        || old_nodes & !maxnode_mask != 0
        || new_nodes & !maxnode_mask != 0
        || old_nodes & !online_mask != 0
        || new_nodes & !online_mask != 0
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let Some(as_ref) = current_address_space() else {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    };
    // SAFETY: the current task owns/uses this live address space.
    match unsafe { as_ref.migrate_pages_between(old_nodes, new_nodes) } {
        Ok(failed) => ctx.set_return(SyscallReturn::ok(failed as u64)),
        Err(_) => ctx.set_return(SyscallReturn::ok((-22i64) as u64)),
    }
}
