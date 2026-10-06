#[allow(unused_imports)]
use super::*;

/// `kcmp(pid1, pid2, type, idx1, idx2)` — compare whether two processes
/// share a kernel resource. Returns 0 (equal), 1/2 (a kernel-pointer
/// ordering), or a negative errno. NARF compares address-space identity
/// for KCMP_VM and otherwise orders by task id.
pub(crate) fn sys_kcmp(ctx: &mut dyn TrapContext) {
    const KCMP_VM: u64 = 1;
    const KCMP_TYPES: u64 = 8;
    let a = *ctx.args();
    let kind = a.arg2;
    let me = current_task_id();
    // `kernel/kcmp.c:146-149`: both pids are looked up FIRST, in the caller's
    // pid namespace, with `find_task_by_vpid` — any thread, a non-leader's tid
    // included; 0 or an unused pid is -ESRCH. Then (:163-167) the caller must
    // pass `ptrace_may_access(PTRACE_MODE_READ_REALCREDS)` on both (-EPERM),
    // and only then does the `switch (type)` reject an unknown type with
    // -EINVAL. Validating the type first answered EINVAL for a missing task.
    let (t1, t2) = match (
        find_task_by_vpid(me, a.arg0 as i32),
        find_task_by_vpid(me, a.arg1 as i32),
    ) {
        (Some(x), Some(y)) => (x, y),
        _ => {
            ctx.set_return(errno_ret(ESRCH));
            return;
        }
    };
    if !ptrace_may_access(me, t1) || !ptrace_may_access(me, t2) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    if kind >= KCMP_TYPES {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    if t1 == t2 {
        // The same task shares every resource with itself.
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let result: u64 = if kind == KCMP_VM {
        // CLONE_THREAD requires CLONE_VM: two threads of one group share
        // `task->mm` by construction.
        if same_thread_group(t1, t2) {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        let a1 = narf_scheduler::address_space_of(narf_scheduler::TaskId(t1));
        let a2 = narf_scheduler::address_space_of(narf_scheduler::TaskId(t2));
        match (a1, a2) {
            (Some(x), Some(y)) if Arc::ptr_eq(&x, &y) => 0,
            _ => {
                if t1 < t2 {
                    1
                } else {
                    2
                }
            }
        }
    } else if t1 < t2 {
        1
    } else {
        2
    };
    ctx.set_return(SyscallReturn::ok(result));
}
