#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::__sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid)`.
///
/// ```text
/// /* check for no-op */
/// if ((rgid == (gid_t) -1 || gid_eq(krgid, old->gid)) &&
///     (egid == (gid_t) -1 || (gid_eq(kegid, old->egid) &&
///                             gid_eq(kegid, old->fsgid))) &&
///     (sgid == (gid_t) -1 || gid_eq(ksgid, old->sgid)))
///         return 0;
///
/// rgid_new = rgid != (gid_t) -1        && !gid_eq(krgid, old->gid) &&
///            !gid_eq(krgid, old->egid) && !gid_eq(krgid, old->sgid);
/// egid_new = ... ; sgid_new = ... ;
/// if ((rgid_new || egid_new || sgid_new) &&
///     !ns_capable_setid(old->user_ns, CAP_SETGID))
///         return -EPERM;
///
/// if (rgid != (gid_t) -1) new->gid  = krgid;
/// if (egid != (gid_t) -1) new->egid = kegid;
/// if (sgid != (gid_t) -1) new->sgid = ksgid;
/// new->fsgid = new->egid;
/// ```
///
/// The gid twin of [`sys_setresuid`]. "New" means an id that is not already
/// one of the three the task holds; unlike the `setre*id` pair, all three
/// arguments draw from the SAME source set {gid, egid, sgid}.
///
/// Three things were wrong here, and they compounded:
///
///   * there was no permission check at all, so any task could take any
///     group. `setgid` has always checked CAP_SETGID, so the guard existed
///     — it was just reachable around. fsgid follows egid, so this handed
///     an unprivileged caller the group half of every DAC decision over any
///     file whose group it chose to claim.
///   * `sgid` was never written, so the saved gid could not be set and a
///     privileged caller could not establish one to drop to and restore.
///   * the ids were not assigned per-field: the handler picked egid if
///     given and rgid otherwise, then wrote that single value to BOTH gid
///     and egid. `setresgid(100, 200, -1)` left the real gid at 200.
pub(crate) fn sys_setresgid(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
    const NOCHANGE: u32 = u32::MAX; // (gid_t)-1
    let a = *ctx.args();
    let (rgid, egid, sgid) = (a.arg0 as u32, a.arg1 as u32, a.arg2 as u32);
    let task = current_task_id();
    let old = read_uidgid(task);

    // `/* check for no-op */` — note it compares egid against BOTH old.egid
    // and old.fsgid, so a caller whose fsgid was moved by setfsgid does not
    // get the early return.
    if (rgid == NOCHANGE || rgid == old.gid)
        && (egid == NOCHANGE || (egid == old.egid && egid == old.fsgid))
        && (sgid == NOCHANGE || sgid == old.sgid)
    {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // "new" means: requested, and not already one of the three ids held.
    let is_new = |v: u32| v != NOCHANGE && v != old.gid && v != old.egid && v != old.sgid;
    if (is_new(rgid) || is_new(egid) || is_new(sgid)) && !capable_in_own_ns(CAP_SETGID) {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }

    let ok = write_uidgid(task, |e| {
        if rgid != NOCHANGE {
            e.gid = rgid;
        }
        if egid != NOCHANGE {
            e.egid = egid;
        }
        if sgid != NOCHANGE {
            e.sgid = sgid;
        }
        // `new->fsgid = new->egid;` — the POSSIBLY-UPDATED effective gid.
        e.fsgid = e.egid;
    });
    ctx.set_return(SyscallReturn::ok(if ok { 0 } else { (-EPERM) as u64 }));
}
