#[allow(unused_imports)]
use super::*;

/// `block/ioprio.c::SYSCALL_DEFINE3(ioprio_set, int, which, int, who,
/// int, ioprio)`.
///
/// ```text
/// ret = ioprio_check_cap(ioprio);
/// if (ret) return ret;
/// ret = -ESRCH;
/// /* per selected task: */ ret = set_task_ioprio(p, ioprio);
/// ```
///
/// `ioprio_check_cap` runs FIRST, before any task is selected, so an
/// invalid class is -EINVAL even when `who` also names nothing. Each
/// selected task then passes `set_task_ioprio`'s owner check.
///
/// WHO_PGRP and WHO_USER previously keyed a `(which, who)` tuple, so they
/// wrote a slot no `ioprio_get` on a member would ever read; the table is
/// now per-task, as in Linux where ioprio lives in the task's io_context.
pub(crate) fn sys_ioprio_set(ctx: &mut dyn TrapContext) {
    const IOPRIO_WHO_PROCESS: i64 = 1;
    const IOPRIO_WHO_PGRP: i64 = 2;
    const IOPRIO_WHO_USER: i64 = 3;
    let args = *ctx.args();
    let which = args.arg0 as i32 as i64;
    let who = args.arg1 as i32;
    let ioprio = args.arg2 as i32 as u32;

    // `ioprio_check_cap(ioprio)` runs before the `which` switch.
    if let Err(e) = ioprio_check_cap(ioprio) {
        ctx.set_return(errno_ret(e));
        return;
    }
    let scope = match which {
        IOPRIO_WHO_PROCESS => WhoScope::Process,
        IOPRIO_WHO_PGRP => WhoScope::Pgrp,
        IOPRIO_WHO_USER => WhoScope::User,
        _ => {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
    };
    // `ret = -ESRCH;` then one `set_task_ioprio` per selected task. How a
    // failure propagates differs by scope, and both shapes are Linux's:
    //
    //   * WHO_PGRP: `if (ret) break;` sits inside `do_each_pid_thread`,
    //     whose `break` leaves only the per-THREAD loop — the walk carries
    //     on to the next process and overwrites `ret`. The group answer is
    //     the last process's.
    //   * WHO_USER: `if (ret) goto free_uid;` — the first refusal ends the
    //     walk and is the answer.
    let targets = resolve_who_targets(scope, who, current_task_id());
    let mut ret: i64 = -ESRCH;
    for t in targets {
        ret = match set_task_ioprio(t, ioprio) {
            Ok(()) => 0,
            Err(e) => -e,
        };
        if ret != 0 && scope == WhoScope::User {
            break;
        }
    }
    ctx.set_return(SyscallReturn::ok(ret as u64));
}

/// `block/ioprio.c::ioprio_check_cap`.
///
/// ```text
/// switch (IOPRIO_PRIO_CLASS(ioprio)) {
/// case IOPRIO_CLASS_RT:
///         if (!capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_NICE))
///                 return -EPERM;
///         fallthrough;
/// case IOPRIO_CLASS_BE:   /* level range */          break;
/// case IOPRIO_CLASS_IDLE:                             break;
/// case IOPRIO_CLASS_NONE: if (level) return -EINVAL;  break;
/// case IOPRIO_CLASS_INVALID:
/// default:                return -EINVAL;
/// }
/// ```
///
/// Only classes 0..=3 exist. Classes 4..=7 used to be accepted because the
/// check was `class >= IOPRIO_NR_CLASSES` — the size of the class FIELD,
/// not the number of defined classes — and `IOPRIO_CLASS_NONE` with a
/// non-zero level (meaningless: NONE means "derive from nice") was stored.
///
/// The RT class is privileged even though NARF has no I/O scheduler: the
/// value round-trips through ioprio_get, so an unprivileged task would
/// otherwise read back IOPRIO_CLASS_RT and believe it held a real-time I/O
/// reservation it was never granted.
fn ioprio_check_cap(ioprio: u32) -> Result<(), i64> {
    const IOPRIO_CLASS_NONE: u32 = 0;
    const IOPRIO_CLASS_RT: u32 = 1;
    const IOPRIO_CLASS_BE: u32 = 2;
    const IOPRIO_CLASS_IDLE: u32 = 3;
    const IOPRIO_LEVEL_MASK: u32 = 0x7;
    match ioprio >> 13 {
        IOPRIO_CLASS_RT => {
            if !capable(CAP_SYS_ADMIN) && !capable(CAP_SYS_NICE) {
                return Err(EPERM);
            }
            Ok(())
        }
        IOPRIO_CLASS_BE | IOPRIO_CLASS_IDLE => Ok(()),
        IOPRIO_CLASS_NONE if ioprio & IOPRIO_LEVEL_MASK != 0 => Err(EINVAL),
        IOPRIO_CLASS_NONE => Ok(()),
        _ => Err(EINVAL),
    }
}

/// `block/ioprio.c::set_task_ioprio` — the per-task owner check:
///
/// ```text
/// tcred = __task_cred(task);
/// if (!uid_eq(tcred->uid, cred->euid) &&
///     !uid_eq(tcred->uid, cred->uid) && !capable(CAP_SYS_NICE))
///         return -EPERM;
/// ```
///
/// Note the shape differs from setpriority's: the TARGET's REAL uid against
/// either of the caller's real or effective uid. It was missing entirely,
/// so any task could re-prioritise any other task's I/O.
fn set_task_ioprio(task: u64, ioprio: u32) -> Result<(), i64> {
    let me = read_uidgid(current_task_id());
    let target_uid = read_uidgid(task).uid;
    if target_uid != me.euid && target_uid != me.uid && !capable(CAP_SYS_NICE) {
        return Err(EPERM);
    }
    ioprio_set_task(task, ioprio);
    Ok(())
}
