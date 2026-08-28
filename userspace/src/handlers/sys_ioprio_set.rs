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
    // LINUX-GAP: the CAP_SYS_NICE / CAP_SYS_ADMIN requirement for
    // IOPRIO_CLASS_RT is not enforced — NARF has no I/O scheduler for the
    // class to mean anything to, so gating it would refuse a request that
    // is already inert.
    if ioprio >> 13 >= IOPRIO_NR_CLASSES {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
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
