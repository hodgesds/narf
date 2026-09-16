#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::__sys_setfsgid(gid_t gid)` — the gid twin of
/// [`sys_setfsuid`], with the same shape and the same stakes.
///
/// ```text
/// if (gid_eq(kgid, old->gid)  || gid_eq(kgid, old->egid)  ||
///     gid_eq(kgid, old->sgid) || gid_eq(kgid, old->fsgid) ||
///     ns_capable_setid(old->user_ns, CAP_SETGID)) {
///         if (!gid_eq(kgid, old->fsgid))
///                 new->fsgid = kgid;
/// }
/// return old_fsgid;
/// ```
///
/// This too wrote unconditionally. `fsgid` is the group half of every DAC
/// decision, so `setfsgid(0)` handed an unprivileged task group-0 access to
/// every file — and, like `setfsuid`, the syscall cannot report the refusal,
/// so nothing surfaced it.
pub(crate) fn sys_setfsgid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let new = ctx.args().arg0 as u32;
    let old = read_uidgid(task);
    let old_fsgid = old.fsgid;
    if new == u32::MAX {
        ctx.set_return(SyscallReturn::ok(old_fsgid as u64));
        return;
    }
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial() && !uns.gid_is_mapped(new) {
            ctx.set_return(SyscallReturn::ok(old_fsgid as u64));
            return;
        }
    }
    let permitted = new == old.gid
        || new == old.egid
        || new == old.sgid
        || new == old.fsgid
        || capable_in_own_ns(CAP_SETGID);
    if permitted && new != old_fsgid {
        let _ = write_uidgid(task, |e| e.fsgid = new);
    }
    ctx.set_return(SyscallReturn::ok(old_fsgid as u64));
}
