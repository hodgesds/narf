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
    if a.arg2 > 64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let nodemask = if a.arg1 != 0 {
        let mut bytes = [0u8; 8];
        // SAFETY: copy_from_user validates the one-word nodemask.
        if unsafe { copy_from_user(&mut bytes, a.arg1) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
        u64::from_ne_bytes(bytes)
    } else {
        0
    };
    let maxnode_mask = if a.arg2 == 0 || a.arg2 == 64 {
        u64::MAX
    } else {
        (1u64 << a.arg2) - 1
    };
    let online = numa_node_count().min(64);
    let online_mask = if online == 64 {
        u64::MAX
    } else {
        (1u64 << online) - 1
    };
    if nodemask & !maxnode_mask != 0 || nodemask & !online_mask != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if !mpol_policy_shape_valid(mode, nodemask) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let task = current_task_id();
    let allowed = narf_scheduler::task_mems_allowed(task) & online_mask;
    if !mpol_initial_nodemask_valid(mode, nodemask, allowed) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let mut g = MEMPOLICY_TABLE.lock();
    g.get_or_insert_with(alloc::collections::BTreeMap::new)
        .insert(
            task,
            StoredPolicy {
                mode,
                nodemask,
                home_node: u32::MAX,
            },
        );
    ctx.set_return(SyscallReturn::ok(0));
}
