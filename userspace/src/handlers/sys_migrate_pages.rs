#[allow(unused_imports)]
use super::*;

/// `migrate_pages(pid, maxnode, old_nodes, new_nodes)` — migrate the
/// caller's resident private pages between NUMA node sets.
///
/// `mm/mempolicy.c::kernel_migrate_pages` fixes both the codes and the order
/// in which they are decided:
///
/// ```text
///     err = get_nodes(old, old_nodes, maxnode);   /* -EINVAL / -EFAULT */
///     if (err) goto out;
///     err = get_nodes(new, new_nodes, maxnode);   /* -EINVAL / -EFAULT */
///     if (err) goto out;
///     task = pid ? find_task_by_vpid(pid) : current;
///     if (!task) { err = -ESRCH; goto out; }
///     err = -EINVAL;
///     if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
///             err = -EPERM; goto out_put;
///     }
/// ```
///
/// Two divergences mattered here.
///
/// **ESRCH vs EPERM.** A pid that does not resolve is ESRCH; only a pid that
/// *does* resolve but fails the ptrace check is EPERM. `numactl --all
/// --pid=N`, and every NUMA balancer that walks `/proc` and migrates each
/// process it finds, races process exit constantly: ESRCH means "it died,
/// move on to the next pid", EPERM means "you are not privileged enough" and
/// makes the tool abort with a permissions diagnostic that sends the operator
/// hunting for a capability that was never the problem.
///
/// **Order.** The node-mask arguments are validated *before* the pid is
/// resolved, so a malformed nodemask beats a stale pid. Doing the pid first
/// reported ESRCH/EPERM for a request that Linux rejects as EINVAL/EFAULT
/// regardless of which process it named.
pub(crate) fn sys_migrate_pages(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    // get_nodes() x2 — both node masks are read and validated before the
    // target task is looked up.
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

    let task = current_task_id();
    let visible_pid = task_to_pid_raw(task).unwrap_or(task);
    // Linux (mm/mempolicy.c) resolves `pid` via find_task_by_vpid — in the
    // CALLER's pid namespace. Translate the inner pid to its outer ProcessId
    // before the self-comparison, so a container naming itself by getpid() (an
    // inner value) is not rejected with a spurious EPERM. Audit finding #20.
    if a.arg0 != 0 {
        match accept_pid_from(task, a.arg0) {
            Some(outer) if outer == task || outer == visible_pid => {}
            // The pid did not resolve in the caller's namespace at all.
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
            // It resolved to some outer id: ESRCH only if no task answers to
            // it (find_task_by_vpid returned NULL), otherwise the
            // ptrace_may_access denial, which is EPERM. Same existence probe
            // sys_sched_getaffinity uses.
            //
            // LINUX-GAP: NARF cannot address a foreign mm here, so every live
            // task other than the caller is refused rather than credential-
            // checked; Linux would let a privileged caller through.
            Some(outer) => {
                let live = pid_to_task_raw(outer).is_some()
                    || narf_scheduler::task_affinity(narf_scheduler::TaskId(outer)).is_some();
                let errno: i64 = if live { 1 } else { 3 }; // EPERM : ESRCH
                ctx.set_return(SyscallReturn::ok((-errno) as u64));
                return;
            }
        }
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
