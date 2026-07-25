#[allow(unused_imports)]
use super::*;

/// `mbind(addr, len, mode, nodemask, maxnode, flags)` — bind a range to
/// a NUMA policy. Stored per (task, range); the fault path consults it
/// via `resolve_policy` so the binding is enforced on demand-fault.
pub(crate) fn sys_mbind(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let addr = a.arg0;
    let len = a.arg1;
    let mode = a.arg2 as u32;
    if !mpol_mode_valid(mode) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let nodemask = if a.arg3 != 0 {
        read_user_u64(a.arg3)
    } else {
        0
    };
    // Page-align the range like Linux (addr must be page-aligned;
    // EINVAL otherwise).
    if addr & 0xFFF != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let task = current_task_id();
    let mut g = MBIND_TABLE.lock();
    let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
    let ranges = map.entry(task).or_default();
    // Drop any existing exact-overlap entry, then insert; a fresh mbind
    // over the same start replaces the old policy.
    ranges.retain(|&(s, _, _)| s != addr);
    if (mode & !MPOL_MODE_FLAGS) != 0 {
        // MPOL_DEFAULT removes the range binding (Linux semantics).
        ranges.push((addr, len, (mode, nodemask)));
    }
    ctx.set_return(SyscallReturn::ok(0));
}
