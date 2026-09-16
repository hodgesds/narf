#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::__sys_setfsuid(uid_t uid)`.
///
/// ```text
/// old_fsuid = from_kuid_munged(old->user_ns, old->fsuid);
/// kuid = make_kuid(old->user_ns, uid);
/// if (!uid_valid(kuid))
///         return old_fsuid;
/// if (uid_eq(kuid, old->uid)  || uid_eq(kuid, old->euid)  ||
///     uid_eq(kuid, old->suid) || uid_eq(kuid, old->fsuid) ||
///     ns_capable_setid(old->user_ns, CAP_SETUID)) {
///         if (!uid_eq(kuid, old->fsuid)) {
///                 new->fsuid = kuid;
///                 ...
///         }
/// }
/// abort_creds(new);
/// return old_fsuid;
/// ```
///
/// `setfsuid` HAS a permission check. It just does not report failure: the
/// return is the previous fsuid whether the change happened or not, so the
/// refusal is silent and a caller is expected to re-read to confirm.
///
/// This function used to write the new fsuid unconditionally, which is a
/// privilege escalation rather than a conformance gap: `fsuid` is the
/// identity every DAC decision is made against — `may_create`, `may_delete`,
/// `inode_permission`, `inode_owner_or_capable` — so an unprivileged task
/// calling `setfsuid(0)` obtained root's file access and defeated the whole
/// permission layer in one call. Nothing caught it because the syscall
/// cannot report an error, and the test asserted only "returns the old
/// fsuid, never an errno", which is true either way.
///
/// The permitted targets are the caller's OWN four ids. That is what makes
/// the classic NFS-server idiom safe: a server holding CAP_SETUID drops
/// fsuid to the requesting user for one operation and restores it, while an
/// unprivileged process can only ever move fsuid between ids it already has.
pub(crate) fn sys_setfsuid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let new = ctx.args().arg0 as u32;
    let old = read_uidgid(task);
    let old_fsuid = old.fsuid;
    // Every answer from here is `old_fsuid`; only whether the write happens
    // differs. `(uid_t)-1` is a pure query and is never a valid id.
    if new == u32::MAX {
        ctx.set_return(SyscallReturn::ok(old_fsuid as u64));
        return;
    }
    // `make_kuid` + `uid_valid`: in a non-initial user-ns an unmapped id is
    // INVALID_UID, and the change is refused. The host root-ns maps
    // everything.
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial() && !uns.uid_is_mapped(new) {
            ctx.set_return(SyscallReturn::ok(old_fsuid as u64));
            return;
        }
    }
    let permitted = new == old.uid
        || new == old.euid
        || new == old.suid
        || new == old.fsuid
        || capable_in_own_ns(CAP_SETUID);
    // `if (!uid_eq(kuid, old->fsuid))` — an unchanged fsuid is not a write,
    // which matters because the write is what runs `cap_emulate_setxuid`.
    if permitted && new != old_fsuid && write_uidgid(task, |e| e.fsuid = new) {
        // `security_task_fix_setuid(new, old, LSM_SETID_FS)` ->
        // `cap_task_fix_setuid`: the LSM_SETID_FS arm moves the FS_SET
        // capabilities with the fs uid rather than clearing the whole set,
        // so this is NOT the same transition `setuid` makes.
        cap_emulate_setfsuid(task, old_fsuid, new);
    }
    ctx.set_return(SyscallReturn::ok(old_fsuid as u64));
}
