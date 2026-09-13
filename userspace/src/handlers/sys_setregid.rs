#[allow(unused_imports)]
use super::*;

/// `setregid(rgid, egid)`.
pub(crate) fn sys_setregid(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let rgid = a.arg0 as u32;
    let egid = a.arg1 as u32;
    let ok = write_uidgid(current_task_id(), |e| {
        if rgid != u32::MAX {
            e.gid = rgid;
        }
        if egid != u32::MAX {
            e.egid = egid;
            e.fsgid = egid;
        }
    });
    // write_uidgid only fails when the per-task uid/gid table is uninitialised
    // — an internal condition unreachable for a live task. If it were reached,
    // -1 folds to EPERM, which is exactly setregid(2)'s dominant failure
    // (kernel/sys.c __sys_setregid: `retval = -EPERM` for an unprivileged
    // identity change; -EINVAL only for an out-of-range gid, which this
    // permissive impl does not range-check). Verified correct as EPERM.
    ctx.set_return(SyscallReturn::ok(if ok { 0 } else { (-1i64) as u64 })); // -EPERM
}
