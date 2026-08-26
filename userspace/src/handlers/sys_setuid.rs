#[allow(unused_imports)]
use super::*;

/// `setuid(uid)` — Linux `__sys_setuid` (kernel/sys.c): `make_kuid` of an id
/// unmapped in the caller's user-ns is invalid → -EINVAL.
/// LINUX-GAP: without CAP_SETUID a caller may only set uids among its
/// real/effective/saved set (else -EPERM); NARF treats setuid as privileged.
pub(crate) fn sys_setuid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let uid = ctx.args().arg0 as u32;
    // In a non-root user-ns, setuid is only allowed to an id mapped in
    // the ns (Linux -EINVAL otherwise). The host root-ns is unrestricted.
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial() && !uns.uid_is_mapped(uid) {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
    }
    // A (notionally privileged) setuid sets real, effective, and fs uids.
    if write_uidgid(task, |e| {
        e.uid = uid;
        e.euid = uid;
        e.fsuid = uid;
    }) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        // Internal: the cred table is uninitialized (unreachable for a live
        // task). -EPERM is setuid's permission-failure errno.
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
    }
}
