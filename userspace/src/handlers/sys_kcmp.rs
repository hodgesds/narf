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
    if kind >= KCMP_TYPES {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let me = current_task_id();
    // kcmp interprets pid1/pid2 in the CALLER's pid namespace (Linux
    // kernel/kcmp.c:146 find_task_by_vpid). Translate each inner pid to its
    // outer ProcessId first, then resolve to the scheduler TaskId the
    // comparison keys on. Passing the raw inner pid ordered against whatever
    // ROOT-namespace process owned the same small number. An inner pid not
    // bound in the caller's namespace has no target -> ESRCH. Audit finding #12.
    let resolve = |pid: u64| -> Option<u64> {
        let outer = accept_pid_from(me, pid)?;
        Some(pid_to_task_raw(outer).unwrap_or(outer))
    };
    let (t1, t2) = match (resolve(a.arg0), resolve(a.arg1)) {
        (Some(x), Some(y)) => (x, y),
        _ => {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        }
    };
    if t1 == t2 {
        // The same task shares every resource with itself.
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let result: u64 = if kind == KCMP_VM {
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
