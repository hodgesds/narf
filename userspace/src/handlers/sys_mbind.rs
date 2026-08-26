#[allow(unused_imports)]
use super::*;

/// `mbind(addr, len, mode, nodemask, maxnode, flags)` — bind a range to
/// a NUMA policy. Stored per (task, range); the fault path consults it
/// via `resolve_policy` so the binding is enforced on demand-fault.
///
/// `mm/mempolicy.c::kernel_mbind` runs the mode check, then reads the node
/// mask, and only then enters `do_mbind` where the flag word is judged:
///
/// ```text
///     err = sanitize_mpol_flags(&lmode, &mode_flags);   /* -EINVAL */
///     if (err) return err;
///     err = get_nodes(&nodes, nmask, maxnode);          /* -EINVAL / -EFAULT */
///     if (err) return err;
///     return do_mbind(...):
///         if (flags & ~(unsigned long)MPOL_MF_VALID)          return -EINVAL;
///         if ((flags & MPOL_MF_MOVE_ALL) && !capable(CAP_SYS_NICE)) return -EPERM;
///         if (start & ~PAGE_MASK)                             return -EINVAL;
///         len = PAGE_ALIGN(len); end = start + len;
///         if (end < start)                                    return -EINVAL;
///         if (end == start)                                   return 0;
/// ```
///
/// So a bad `nodemask` **pointer** beats a bad flag word: `mbind` with an
/// unreadable mask reports EFAULT even when `flags` is also junk. A caller
/// that gets EINVAL where Linux gives EFAULT concludes its *policy* is
/// unsupported and permanently disables NUMA binding, rather than fixing the
/// pointer it passed. Reading the mask before judging `flags` restores that.
pub(crate) fn sys_mbind(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let addr = a.arg0;
    let len = a.arg1;
    let mode = a.arg2 as u32;
    const MPOL_MF_STRICT: u64 = 1 << 0;
    const MPOL_MF_MOVE: u64 = 1 << 1;
    const MPOL_MF_MOVE_ALL: u64 = 1 << 2;
    const MPOL_MF_VALID: u64 = MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;
    if !mpol_mode_valid(mode) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // get_nodes() — before do_mbind's flag validation, so EFAULT wins.
    let nodemask = if a.arg3 != 0 {
        let mut bytes = [0u8; 8];
        // SAFETY: copy_from_user validates the one-word nodemask.
        if unsafe { copy_from_user(&mut bytes, a.arg3) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
        u64::from_ne_bytes(bytes)
    } else {
        0
    };
    if a.arg5 & !MPOL_MF_VALID != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if a.arg5 & MPOL_MF_MOVE_ALL != 0 {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM: no ambient CAP_SYS_NICE.
        return;
    }
    if !mpol_policy_shape_valid(mode, nodemask) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // Page-align the range like Linux (addr must be page-aligned;
    // EINVAL otherwise).
    if addr & 0xFFF != 0 || a.arg4 > 64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let len = match len.checked_add(4095) {
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
    let Some(end) = addr.checked_add(len) else {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    };
    let maxnode_mask = if a.arg4 == 0 || a.arg4 == 64 {
        u64::MAX
    } else {
        (1u64 << a.arg4) - 1
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
    let task = current_task_id();
    if mode & MPOL_F_NUMA_BALANCING != 0 {
        start_numa_balance_range(task, addr);
    } else {
        ensure_numa_balance_state(task);
    }
    let allowed = narf_scheduler::task_mems_allowed(task) & online_mask;
    if !mpol_initial_nodemask_valid(mode, nodemask, allowed) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let mut flags = a.arg5;
    if (mode & !MPOL_MODE_FLAGS) == 0 {
        flags &= !MPOL_MF_STRICT;
    }
    let mut strict_failed = false;
    if flags & (MPOL_MF_STRICT | MPOL_MF_MOVE) != 0 {
        let policy_nodes = if nodemask == 0 {
            allowed
        } else {
            mpol_effective_nodemask(
                StoredPolicy {
                    mode,
                    nodemask,
                    home_node: u32::MAX,
                },
                allowed,
            )
        };
        if policy_nodes == 0 {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
        let Some(as_ref) = current_address_space() else {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        };
        // SAFETY: the current task owns/uses this live address space.
        match unsafe {
            as_ref.conform_range_to_nodes(
                VirtAddr::new(addr),
                len,
                policy_nodes,
                flags & MPOL_MF_MOVE != 0,
            )
        } {
            Ok(failed) => strict_failed = failed != 0 && flags & MPOL_MF_STRICT != 0,
            Err(narf_memory::AddressSpaceError::Unmapped) => {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            Err(_) => {
                ctx.set_return(SyscallReturn::ok((-12i64) as u64)); // ENOMEM
                return;
            }
        }
    }
    {
        let mut g = MBIND_TABLE.lock();
        let map = g.get_or_insert_with(alloc::collections::BTreeMap::new);
        let ranges = map.entry(task).or_default();
        let old = core::mem::take(ranges);
        for (start, old_len, policy) in old {
            let old_end = start.saturating_add(old_len);
            if start >= end || old_end <= addr {
                ranges.push((start, old_len, policy));
                continue;
            }
            if start < addr {
                ranges.push((start, addr - start, policy));
            }
            if old_end > end {
                ranges.push((end, old_end - end, policy));
            }
        }
        if (mode & !MPOL_MODE_FLAGS) != 0 {
            // MPOL_DEFAULT removes the range binding (Linux semantics).
            ranges.push((
                addr,
                len,
                StoredPolicy {
                    mode,
                    nodemask,
                    home_node: u32::MAX,
                },
            ));
        }
        ranges.sort_by_key(|&(start, _, _)| start);
    }
    if strict_failed {
        ctx.set_return(SyscallReturn::ok((-5i64) as u64)); // EIO
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
