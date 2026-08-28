#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::__sys_setuid(uid_t uid)`.
///
/// ```text
/// kuid = make_kuid(ns, uid);
/// if (!uid_valid(kuid))                    return -EINVAL;
/// retval = -EPERM;
/// if (ns_capable_setid(old->user_ns, CAP_SETUID)) {
///         new->suid = new->uid = kuid;
///         ...
/// } else if (!uid_eq(kuid, old->uid) && !uid_eq(kuid, new->suid)) {
///         goto error;                      /* -EPERM */
/// }
/// new->fsuid = new->euid = kuid;
/// ```
///
/// The two branches differ in WHAT THEY WRITE, not just in whether they
/// succeed, and that asymmetry is the whole point of the call:
///
///   * with CAP_SETUID, real + saved + effective + fs all move, so the
///     change is irreversible — the caller cannot switch back.
///   * without it, only effective and fs move; real and saved are left
///     alone, which is exactly what lets a set-uid program drop to the
///     invoking user and later restore itself from `suid`.
///
/// Collapsing both into "set uid = euid = fsuid unconditionally" (the
/// previous behaviour) meant any process could become uid 0 by asking,
/// and that a legitimate temporary drop became permanent.
pub(crate) fn sys_setuid(ctx: &mut dyn TrapContext) {
    const EPERM: i64 = 1;
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
    let old = read_uidgid(task);
    if capable_in_own_ns(CAP_SETUID) {
        // Privileged: every id moves.
        if !write_uidgid(task, |e| {
            e.uid = uid;
            e.suid = uid;
            e.euid = uid;
            e.fsuid = uid;
        }) {
            // Internal: the cred table is uninitialized (unreachable for a
            // live task). -EPERM is setuid's permission-failure errno.
            ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
            return;
        }
    } else {
        // Unprivileged: only to the real or the saved uid, and only the
        // effective/fs ids move.
        if uid != old.uid && uid != old.suid {
            ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
            return;
        }
        if !write_uidgid(task, |e| {
            e.euid = uid;
            e.fsuid = uid;
        }) {
            ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
            return;
        }
    }
    // `security_task_fix_setuid(new, old, LSM_SETID_*)` -> cap_task_fix_setuid
    // -> cap_emulate_setxuid: the capability sets follow the uid change, so
    // dropping away from root actually drops privilege.
    cap_emulate_setxuid(task, old, read_uidgid(task));
    ctx.set_return(SyscallReturn::ok(0));
}
