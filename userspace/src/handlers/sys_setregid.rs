#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::__sys_setregid(gid_t rgid, gid_t egid)`.
///
/// ```text
/// retval = -EPERM;
/// if (rgid != (gid_t) -1) {
///         if (gid_eq(old->gid, krgid) ||
///             gid_eq(old->egid, krgid) ||
///             ns_capable_setid(old->user_ns, CAP_SETGID))
///                 new->gid = krgid;
///         else
///                 goto error;
/// }
/// if (egid != (gid_t) -1) {
///         if (gid_eq(old->gid, kegid) ||
///             gid_eq(old->egid, kegid) ||
///             gid_eq(old->sgid, kegid) ||
///             ns_capable_setid(old->user_ns, CAP_SETGID))
///                 new->egid = kegid;
///         else
///                 goto error;
/// }
/// if (rgid != (gid_t) -1 ||
///     (egid != (gid_t) -1 && !gid_eq(kegid, old->gid)))
///         new->sgid = new->egid;
/// new->fsgid = new->egid;
/// ```
///
/// The gid twin of [`sys_setreuid`], and the same two details carry over:
/// the permitted source sets DIFFER between the two arguments (a new real
/// gid may come from {gid, egid}, a new effective gid also from sgid), and
/// the saved gid is rewritten as a side effect whenever the real gid was
/// touched or the effective gid moved somewhere other than the old real gid.
///
/// This function previously performed NO permission check: it wrote whatever
/// it was given and returned 0. `setgid` has always checked CAP_SETGID, so
/// the guard was there — but a caller could route around it through here, or
/// through `setresgid`, and take any group it liked. That matters beyond the
/// id itself: fsgid follows egid, so an unprivileged task could hand itself
/// the group half of every DAC decision — `may_create`, `may_delete`, the
/// inode mode check, the setgid-directory rules — over any file whose group
/// it chose to claim.
pub(crate) fn sys_setregid(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
    const NOCHANGE: u32 = u32::MAX; // (gid_t)-1
    let a = *ctx.args();
    let rgid = a.arg0 as u32;
    let egid = a.arg1 as u32;
    let task = current_task_id();
    let old = read_uidgid(task);

    if rgid != NOCHANGE && rgid != old.gid && rgid != old.egid && !capable_in_own_ns(CAP_SETGID) {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }
    if egid != NOCHANGE
        && egid != old.gid
        && egid != old.egid
        && egid != old.sgid
        && !capable_in_own_ns(CAP_SETGID)
    {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }

    // write_uidgid only fails when the per-task uid/gid table is
    // uninitialised — an internal condition unreachable for a live task.
    // -EPERM is setregid(2)'s dominant failure, so it is the fold.
    let ok = write_uidgid(task, |e| {
        if rgid != NOCHANGE {
            e.gid = rgid;
        }
        if egid != NOCHANGE {
            e.egid = egid;
        }
        // `if (rgid != -1 || (egid != -1 && !gid_eq(kegid, old->gid)))`
        if rgid != NOCHANGE || (egid != NOCHANGE && egid != old.gid) {
            e.sgid = e.egid;
        }
        e.fsgid = e.egid;
    });
    ctx.set_return(SyscallReturn::ok(if ok { 0 } else { (-EPERM) as u64 }));
}
