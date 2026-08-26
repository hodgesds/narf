#[allow(unused_imports)]
use super::*;

/// `setgid(gid)` — Linux `__sys_setgid` (kernel/sys.c): `make_kgid` of an id
/// unmapped in the caller's user-ns is invalid → -EINVAL.
/// LINUX-GAP: without CAP_SETGID a caller may only set gids among its
/// real/effective/saved set (else -EPERM); NARF treats setgid as privileged.
pub(crate) fn sys_setgid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let gid = ctx.args().arg0 as u32;
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial() && !uns.gid_is_mapped(gid) {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
    }
    if write_uidgid(task, |e| {
        e.gid = gid;
        e.egid = gid;
        e.fsgid = gid;
    }) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        // Internal: the cred table is uninitialized (unreachable for a live
        // task). -EPERM is setgid's permission-failure errno.
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
    }
}
