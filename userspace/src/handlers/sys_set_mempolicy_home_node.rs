#[allow(unused_imports)]
use super::*;

/// `set_mempolicy_home_node(addr, len, home_node, flags)` — update the
/// distance anchor of existing MPOL_BIND policies overlapping the range.
pub(crate) fn sys_set_mempolicy_home_node(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    if a.arg3 != 0 || a.arg0 & 0xFFF != 0 || a.arg2 >= numa_node_count() as u64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let len = match a.arg1.checked_add(4095) {
        Some(v) => v & !4095,
        None => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        }
    };
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let Some(end) = a.arg0.checked_add(len) else {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    };
    let task = current_task_id();
    let mut changed = false;
    if let Some(ranges) = MBIND_TABLE.lock().as_mut().and_then(|m| m.get_mut(&task)) {
        let old = core::mem::take(ranges);
        let mut updated = alloc::vec::Vec::with_capacity(old.len() + 2);
        let mut iter = old.into_iter();
        while let Some((start, range_len, policy)) = iter.next() {
            let range_end = start.saturating_add(range_len);
            if start >= end || range_end <= a.arg0 {
                updated.push((start, range_len, policy));
                continue;
            }
            if (policy.mode & !MPOL_MODE_FLAGS) != narf_memory::MPOL_BIND {
                updated.push((start, range_len, policy));
                updated.extend(iter);
                *ranges = updated;
                ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
                return;
            }
            let overlap_start = start.max(a.arg0);
            let overlap_end = range_end.min(end);
            if start < overlap_start {
                updated.push((start, overlap_start - start, policy));
            }
            let mut home_policy = policy;
            home_policy.home_node = a.arg2 as u32;
            updated.push((overlap_start, overlap_end - overlap_start, home_policy));
            if overlap_end < range_end {
                updated.push((overlap_end, range_end - overlap_end, policy));
            }
            changed = true;
        }
        *ranges = updated;
    }
    if changed {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // ENOENT
    }
}
