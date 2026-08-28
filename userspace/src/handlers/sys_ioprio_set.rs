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
/// invalid class is -EINVAL even when `who` also names nothing.
///
/// WHO_PGRP and WHO_USER previously keyed a `(which, who)` tuple, so they
/// wrote a slot no `ioprio_get` on a member would ever read; the table is
/// now per-task, as in Linux where ioprio lives in the task's io_context.
pub(crate) fn sys_ioprio_set(ctx: &mut dyn TrapContext) {
    const ESRCH: i64 = 3;
    const EINVAL: i64 = 22;
    const IOPRIO_WHO_PROCESS: i64 = 1;
    const IOPRIO_WHO_PGRP: i64 = 2;
    const IOPRIO_WHO_USER: i64 = 3;
    /// `IOPRIO_CLASS_NONE/RT/BE/IDLE` occupy 0..=3; `IOPRIO_NR_CLASSES` is
    /// 8, and anything above it is rejected by `ioprio_check_cap`.
    const IOPRIO_NR_CLASSES: u32 = 8;
    let args = *ctx.args();
    let which = args.arg0 as i32 as i64;
    let who = args.arg1 as i32;
    let ioprio = args.arg2 as i32 as u32;

    // `ioprio_check_cap(ioprio)` — the class must be a defined one. Runs
    // before the `which` switch in Linux.
    //
    if ioprio >> 13 >= IOPRIO_NR_CLASSES {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // `ioprio_check_cap`: the real-time class is privileged.
    //
    //     case IOPRIO_CLASS_RT:
    //             if (!capable(CAP_SYS_NICE) && !capable(CAP_SYS_ADMIN))
    //                     return -EPERM;
    //
    // A previous note argued this was not worth enforcing because NARF has
    // no I/O scheduler, so the class "is already inert". That reasoning
    // does not hold for a REQUEST: the value round-trips through
    // ioprio_get, so an unprivileged task could read back
    // IOPRIO_CLASS_RT and conclude it holds a real-time I/O reservation it
    // was never granted. Refusing it costs nothing and keeps the reported
    // state honest for whenever a scheduler does arrive.
    const IOPRIO_CLASS_RT: u32 = 1;
    if ioprio >> 13 == IOPRIO_CLASS_RT
        && !capable(CAP_SYS_NICE)
        && !capable(CAP_SYS_ADMIN)
    {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
        return;
    }
    let scope = match which {
        IOPRIO_WHO_PROCESS => WhoScope::Process,
        IOPRIO_WHO_PGRP => WhoScope::Pgrp,
        IOPRIO_WHO_USER => WhoScope::User,
        _ => {
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
            return;
        }
    };
    let targets = resolve_who_targets(scope, who, current_task_id());
    if targets.is_empty() {
        ctx.set_return(SyscallReturn::ok((-ESRCH) as u64));
        return;
    }
    let mut g = IOPRIO_TABLE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    for t in targets {
        m.insert(t, ioprio);
    }
    drop(g);
    ctx.set_return(SyscallReturn::ok(0));
}
