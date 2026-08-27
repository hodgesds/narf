#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::SYSCALL_DEFINE2(setpgid, pid_t, pid, pid_t, pgid)`.
///
/// ```text
/// if (!pid)  pid = task_pid_vnr(group_leader);
/// if (!pgid) pgid = pid;
/// if (pgid < 0) return -EINVAL;
///
/// err = -ESRCH;
/// p = find_task_by_vpid(pid);
/// if (!p) goto out;
///
/// err = -EINVAL;
/// if (!thread_group_leader(p)) goto out;
///
/// if (same_thread_group(p->real_parent, group_leader)) {
///         err = -EPERM;
///         if (task_session(p) != task_session(group_leader)) goto out;
///         err = -EACCES;
///         if (!(p->flags & PF_FORKNOEXEC)) goto out;
/// } else {
///         err = -ESRCH;
///         if (p != group_leader) goto out;
/// }
///
/// err = -EPERM;
/// if (p->signal->leader) goto out;
///
/// pgrp = task_pid(p);
/// if (pgid != pid) {
///         pgrp = find_vpid(pgid);
///         g = pid_task(pgrp, PIDTYPE_PGID);
///         if (!g || task_session(g) != task_session(group_leader)) goto out;
/// }
/// ...
/// err = 0;
/// ```
///
/// This handler previously validated NOTHING: it translated both arguments
/// and inserted into `PGID_TABLE` unconditionally, returning 0. That is a
/// worse failure than a wrong errno — a shell's job-control setup could
/// place a process into a group it must not join, or "succeed" at moving a
/// pid that does not exist, and never learn either happened. Every arm
/// below except EACCES is now enforced.
pub(crate) fn sys_setpgid(ctx: &mut dyn TrapContext) {
    const ESRCH: i64 = 3;
    const EPERM: i64 = 1;
    const EINVAL: i64 = 22;
    let args = *ctx.args();
    // `pid_t` is `int`: the arguments are the low 32 bits, sign-extended.
    // Reading the full register let a negative pgid arrive as a huge
    // positive u64 and slip past the `pgid < 0` rejection entirely.
    let pid_arg = args.arg0 as i32;
    let pgid_arg = args.arg1 as i32;

    let me = process_state_key(current_task_id());
    // `if (!pgid) pgid = pid;` — with `pid` already defaulted to the caller,
    // so a zero pgid always means "the target's own group". Both defaults are
    // resolved in TASK space below rather than by round-tripping the caller
    // through `pgid_to_user`: a visible pid wider than `int` would truncate
    // there, and a truncation that flips the sign bit would send the most
    // common form of this call — setpgid(0, 0) — down the `pid < 0` arm.
    let target_is_self = pid_arg == 0;
    let group_is_target = pgid_arg == 0 || pgid_arg == pid_arg;
    // `if (pgid < 0) return -EINVAL;` — note this fires for a negative pgid
    // even when `pid` also names no task.
    if pgid_arg < 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // A negative `pid` can never resolve; find_task_by_vpid gives -ESRCH.
    if pid_arg < 0 {
        ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
        return;
    }

    // `find_task_by_vpid(pid)` — resolved in the caller's pid namespace.
    // `pgid_from_user` performs exactly that inner -> outer -> TaskId hop.
    let target = if target_is_self {
        me
    } else {
        let t = pgid_from_user(pid_arg as u64);
        if t == 0 { 0 } else { process_state_key(t) }
    };
    // The caller always resolves, even in syscall-unit fixtures that never
    // populate the scheduler's task registry; any other target must be live.
    let target_exists =
        target != 0 && (target == me || crate::task::task_get(target).is_some());
    if !target_exists {
        ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
        return;
    }

    // `if (!thread_group_leader(p)) return -EINVAL;` — a bare thread cannot
    // be moved between process groups. NARF marks a thread by mapping its
    // TaskId onto a DIFFERENT process key; a group leader is its own key.
    if process_state_key(target) != target {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }

    let caller_session = read_sid(me);
    if target != me {
        // Linux splits on `same_thread_group(p->real_parent, group_leader)`:
        // the target must be either the caller itself or a child of it.
        // PARENT_OF is keyed by the child's ProcessId and stores the parent's
        // TaskId (see `parent_of_set` in sys_fork).
        let target_pid = task_to_pid_raw(target).unwrap_or(target);
        let is_child = parent_of_get(target_pid)
            .map(|parent| process_state_key(parent) == me)
            .unwrap_or(false);
        if !is_child {
            // `err = -ESRCH; if (p != group_leader) goto out;` — a process
            // that is neither the caller nor its child is reported as
            // NON-EXISTENT rather than forbidden, so an unrelated process
            // cannot be probed for existence through setpgid.
            ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
            return;
        }
        // `if (task_session(p) != task_session(group_leader)) return -EPERM;`
        if read_sid(target) != caller_session {
            ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
            return;
        }
        // LINUX-GAP: the `-EACCES` arm (`!(p->flags & PF_FORKNOEXEC)` — the
        // child has already execve'd) has no counterpart; NARF tracks no
        // per-task "has exec'd since fork" flag, so a late setpgid on an
        // already-exec'd child succeeds here where Linux refuses it.
    }

    // `err = -EPERM; if (p->signal->leader) goto out;` — a session leader's
    // process group is its session and cannot be changed.
    if is_session_leader(target) {
        ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
        return;
    }

    // `if (pgid != pid) { pgrp = find_vpid(pgid); g = pid_task(pgrp,
    // PIDTYPE_PGID); if (!g || task_session(g) != task_session(group_leader))
    // goto out; }` — with `err` still -EPERM from the session-leader check
    // above. Joining an EXISTING group is only allowed within the caller's
    // own session. Naming the target's own pid instead is the "become your
    // own group leader" idiom (Linux's `pgrp = task_pid(p)`) and skips that
    // check, which would otherwise be circular for a group this very call
    // brings into existence.
    let group = if group_is_target {
        target
    } else {
        let g = pgid_from_user(pgid_arg as u64);
        if g == 0 { 0 } else { process_state_key(g) }
    };
    let value = if group == target {
        target
    } else {
        match session_of_pgrp(group) {
            Some(session) if session == caller_session => group,
            _ => {
                ctx.set_return(SyscallReturn::ok((-EPERM) as u64));
                return;
            }
        }
    };

    let mut g = PGID_TABLE.lock();
    let Some(m) = g.as_mut() else {
        // PGID_TABLE is boot-initialised; an absent table is a kernel bug,
        // not a caller error. Linux has no such state, so there is no errno
        // to mirror — ESRCH is the closest ("no such process to record").
        ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
        return;
    };
    m.insert(target, value);
    drop(g);
    ctx.set_return(SyscallReturn::ok(0));
}
