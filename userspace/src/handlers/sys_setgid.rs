#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::__sys_setgid(gid_t gid)`.
///
/// ```text
/// if (ns_capable_setid(old->user_ns, CAP_SETGID))
///         new->gid = new->egid = new->sgid = new->fsgid = kgid;
/// else if (gid_eq(kgid, old->gid) || gid_eq(kgid, old->sgid))
///         new->egid = new->fsgid = kgid;
/// else
///         goto error;                      /* -EPERM */
/// ```
///
/// Same shape as `setuid`: the privileged branch moves all four ids and is
/// irreversible; the unprivileged branch is permitted only towards the real
/// or saved gid and moves only the effective and fs ids, so a set-gid
/// program can drop and later restore. Note the condition is written the
/// other way round from setuid's (positive rather than negated) but tests
/// the same two ids.
pub(crate) fn sys_setgid(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
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
    let old = read_uidgid(task);
    let ok = if capable(CAP_SETGID) {
        write_uidgid(task, |e| {
            e.gid = gid;
            e.egid = gid;
            e.sgid = gid;
            e.fsgid = gid;
        })
    } else if gid == old.gid || gid == old.sgid {
        write_uidgid(task, |e| {
            e.egid = gid;
            e.fsgid = gid;
        })
    } else {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    };
    if ok {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        // Internal: the cred table is uninitialized (unreachable for a live
        // task). -EPERM is setgid's permission-failure errno.
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
    }
}
