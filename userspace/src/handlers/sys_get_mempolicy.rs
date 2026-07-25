#[allow(unused_imports)]
use super::*;

/// `get_mempolicy(mode, nodemask, maxnode, addr, flags)` — report the
/// policy in force. Honors the query flags:
/// - `MPOL_F_ADDR`: report the policy covering `addr` (an mbind range,
///   else the task default).
/// - `MPOL_F_NODE` (with `MPOL_F_ADDR`): write the node the page at
///   `addr` would allocate from into `*mode`.
/// - `MPOL_F_MEMS_ALLOWED`: write the set of allowed nodes into the
///   nodemask (all online nodes here).
pub(crate) fn sys_get_mempolicy(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let mode_ptr = a.arg0;
    let nodemask_ptr = a.arg1;
    let addr = a.arg3;
    let flags = a.arg4 as u32;
    let task = current_task_id();
    let valid_flags = MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED;
    if flags & !valid_flags != 0
        || (flags & MPOL_F_MEMS_ALLOWED != 0 && flags & (MPOL_F_NODE | MPOL_F_ADDR) != 0)
        || (addr != 0 && flags & MPOL_F_ADDR == 0)
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let online_nodes = numa_node_count().min(64);
    if nodemask_ptr != 0 && a.arg2 < online_nodes as u64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    if flags & MPOL_F_MEMS_ALLOWED != 0 {
        // Report the cgroup-constrained mask of nodes this task may use.
        let online: u64 = if online_nodes >= 64 {
            u64::MAX
        } else {
            (1u64 << online_nodes) - 1
        };
        let allowed = narf_scheduler::task_mems_allowed(task) & online;
        if nodemask_ptr != 0 {
            // SAFETY: copy_to_user validates the user pointer/length.
            if unsafe { copy_to_user(nodemask_ptr, &allowed.to_le_bytes()) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    let as_ref = if flags & MPOL_F_ADDR != 0 {
        let Some(as_ref) = current_address_space() else {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        };
        if !as_ref.contains_address(VirtAddr::new(addr)) {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
        Some(as_ref)
    } else {
        None
    };

    let policy = if flags & MPOL_F_ADDR != 0 {
        resolve_policy(task, addr)
    } else {
        MEMPOLICY_TABLE
            .lock()
            .as_ref()
            .and_then(|m| m.get(&task).copied())
            .unwrap_or(StoredPolicy::DEFAULT)
    };

    if mode_ptr != 0 {
        let out_word: i32 = if flags & MPOL_F_NODE != 0 && flags & MPOL_F_ADDR != 0 {
            let as_ref = as_ref.expect("MPOL_F_ADDR validated address space");
            let phys = if let Some(phys) = mapped_phys(&as_ref, addr) {
                Some(phys)
            } else {
                publish_mempolicy_for_fault(addr);
                // SAFETY: `addr` belongs to a mapped region in the current
                // live address space; this mirrors Linux lookup_node's GUP
                // fault-in behavior.
                let populated = unsafe { as_ref.demand_alloc_page(VirtAddr::new(addr)).is_ok() };
                clear_mempolicy_for_fault();
                if populated {
                    mapped_phys(&as_ref, addr)
                } else {
                    None
                }
            };
            let Some(phys) = phys else {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            };
            numa_node_for_phys(phys) as i32
        } else if flags & MPOL_F_NODE != 0 {
            if (policy.mode & !MPOL_MODE_FLAGS) != narf_memory::MPOL_INTERLEAVE {
                ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
                return;
            }
            let pol = narf_memory::Mempolicy {
                mode: narf_memory::MPOL_INTERLEAVE,
                nodemask: mpol_effective_nodemask(policy, narf_scheduler::task_mems_allowed(task)),
                allowed: narf_scheduler::task_mems_allowed(task),
                home_node: policy.home_node,
            };
            mempolicy_resolved_node(pol) as i32
        } else {
            policy.mode as i32
        };
        // SAFETY: mode_ptr is the user int out-pointer; copy_to_user validates it.
        if unsafe { copy_to_user(mode_ptr, &out_word.to_le_bytes()) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    }
    if nodemask_ptr != 0 {
        // SAFETY: nodemask_ptr is the user unsigned-long array; copy_to_user validates it.
        let _ = unsafe { copy_to_user(nodemask_ptr, &policy.nodemask.to_le_bytes()) };
    }
    ctx.set_return(SyscallReturn::ok(0));
}
