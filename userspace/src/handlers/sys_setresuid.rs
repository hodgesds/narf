#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::__sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)`.
///
/// ```text
/// /* check for no-op */
/// if ((ruid == -1 || uid_eq(kruid, old->uid)) &&
///     (euid == -1 || (uid_eq(keuid, old->euid) && uid_eq(keuid, old->fsuid))) &&
///     (suid == -1 || uid_eq(ksuid, old->suid)))
///         return 0;
///
/// ruid_new = ruid != -1 && !uid_eq(kruid, old->uid) &&
///            !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid);
/// euid_new = ... ; suid_new = ... ;
/// if ((ruid_new || euid_new || suid_new) &&
///     !ns_capable_setid(old->user_ns, CAP_SETUID))
///         return -EPERM;
///
/// if (ruid != -1) new->uid  = kruid;
/// if (euid != -1) new->euid = keuid;
/// if (suid != -1) new->suid = ksuid;
/// new->fsuid = new->euid;
/// ```
///
/// The rule is a permutation test, not a raise test: an unprivileged
/// caller may shuffle its three ids into any arrangement OF THE IDS IT
/// ALREADY HOLDS, and only introducing a genuinely new id needs
/// CAP_SETUID. That is what lets a set-uid helper swap real and effective
/// back and forth without ever being privileged.
///
/// The previous version collapsed all three arguments onto one uid and
/// always returned 0, so it neither enforced the rule nor kept the three
/// ids distinct enough to express it.
pub(crate) fn sys_setresuid(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
    const NOCHANGE: u32 = u32::MAX; // (uid_t)-1
    let a = *ctx.args();
    let (ruid, euid, suid) = (a.arg0 as u32, a.arg1 as u32, a.arg2 as u32);
    let task = current_task_id();
    let old = read_uidgid(task);

    // `/* check for no-op */` — note it compares euid against BOTH old.euid
    // and old.fsuid, so a caller whose fsuid was moved by setfsuid does not
    // get the early return.
    if (ruid == NOCHANGE || ruid == old.uid)
        && (euid == NOCHANGE || (euid == old.euid && euid == old.fsuid))
        && (suid == NOCHANGE || suid == old.suid)
    {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // "new" means: requested, and not already one of the three ids held.
    let is_new = |v: u32| v != NOCHANGE && v != old.uid && v != old.euid && v != old.suid;
    if (is_new(ruid) || is_new(euid) || is_new(suid)) && !capable(CAP_SETUID) {
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
        if suid != NOCHANGE {
            e.suid = suid;
        }
        // `new->fsuid = new->euid;` — the POSSIBLY-UPDATED effective uid.
        e.fsuid = e.euid;
    });
    // `security_task_fix_setuid(new, old, LSM_SETID_*)` -> cap_task_fix_setuid
    // -> cap_emulate_setxuid: the capability sets follow the uid change, so
    // dropping away from root actually drops privilege.
    if ok {
        cap_emulate_setxuid(task, old, read_uidgid(task));
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
    }
}
