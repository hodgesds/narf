#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::__sys_setreuid(uid_t ruid, uid_t euid)`.
///
/// ```text
/// if (ruid != -1) {
///         new->uid = kruid;
///         if (!uid_eq(old->uid, kruid) && !uid_eq(old->euid, kruid) &&
///             !ns_capable_setid(old->user_ns, CAP_SETUID))
///                 goto error;                     /* -EPERM */
/// }
/// if (euid != -1) {
///         new->euid = keuid;
///         if (!uid_eq(old->uid, keuid) && !uid_eq(old->euid, keuid) &&
///             !uid_eq(old->suid, keuid) &&
///             !ns_capable_setid(old->user_ns, CAP_SETUID))
///                 goto error;                     /* -EPERM */
/// }
/// if (ruid != -1 || (euid != -1 && !uid_eq(keuid, old->uid)))
///         new->suid = new->euid;
/// new->fsuid = new->euid;
/// ```
///
/// Two details that are easy to lose and both matter:
///
///   * the permitted source sets DIFFER between the two arguments — a new
///     real uid may come from {uid, euid}, a new effective uid from
///     {uid, euid, suid}. The saved uid is a legal source for euid only.
///   * the saved uid is rewritten as a SIDE EFFECT, whenever the real uid
///     was touched or the effective uid moved somewhere other than the old
///     real uid. That is what makes `setreuid(-1, other)` a reversible
///     drop but `setreuid(other, other)` a permanent one.
pub(crate) fn sys_setreuid(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
    const NOCHANGE: u32 = u32::MAX; // (uid_t)-1
    let a = *ctx.args();
    let ruid = a.arg0 as u32;
    let euid = a.arg1 as u32;
    let task = current_task_id();
    let old = read_uidgid(task);

    if ruid != NOCHANGE && ruid != old.uid && ruid != old.euid && !capable(CAP_SETUID) {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }
    if euid != NOCHANGE
        && euid != old.uid
        && euid != old.euid
        && euid != old.suid
        && !capable(CAP_SETUID)
    {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }

    let ok = write_uidgid(task, |e| {
        if ruid != NOCHANGE {
            e.uid = ruid;
        }
        if euid != NOCHANGE {
            e.euid = euid;
        }
        // `if (ruid != -1 || (euid != -1 && !uid_eq(keuid, old->uid)))`
        if ruid != NOCHANGE || (euid != NOCHANGE && euid != old.uid) {
            e.suid = e.euid;
        }
        e.fsuid = e.euid;
    });
    ctx.set_return(SyscallReturn::ok(if ok { 0 } else { (-EPERM) as u64 }));
}
