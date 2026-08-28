#[allow(unused_imports)]
use super::*;

/// `block/ioprio.c::SYSCALL_DEFINE2(ioprio_get, int, which, int, who)`.
///
/// ```text
/// int ret = -ESRCH;
/// case IOPRIO_WHO_PGRP:
///         do_each_pid_thread(pgrp, PIDTYPE_PGID, p) {
///                 tmpio = get_task_ioprio(p);
///                 if (tmpio < 0) continue;
///                 if (ret == -ESRCH) ret = tmpio;
///                 else               ret = ioprio_best(ret, tmpio);
///         } while_each_pid_thread(...);
/// ```
///
/// `ioprio_best` keeps the NUMERICALLY LOWER value, which is the HIGHER
/// priority — the encoding is class-major (RT=1 < BE=2 < IDLE=3), so a
/// smaller word is a more urgent request. Reporting the maximum, or the
/// first, would describe a group as less urgent than its most urgent
/// member.
///
/// WHO_PGRP and WHO_USER previously looked their `who` up untranslated
/// against a `(which, who)`-keyed table, so they read a slot nothing ever
/// wrote. The table is now per-task and the selection is shared with
/// getpriority/setpriority.
pub(crate) fn sys_ioprio_get(ctx: &mut dyn TrapContext) {
    const ESRCH: i64 = 3;
    const EINVAL: i64 = 22;
    const IOPRIO_WHO_PROCESS: i64 = 1;
    const IOPRIO_WHO_PGRP: i64 = 2;
    const IOPRIO_WHO_USER: i64 = 3;
    let args = *ctx.args();
    // `int which`, `int who`.
    let which = args.arg0 as i32 as i64;
    let who = args.arg1 as i32;
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
    let g = IOPRIO_TABLE.lock();
    let mut best: Option<u32> = None;
    for t in targets {
        let v = g
            .as_ref()
            .and_then(|m| m.get(&t).copied())
            .unwrap_or(IOPRIO_DEFAULT);
        // `ioprio_best` — the lower word wins.
        best = Some(best.map_or(v, |b| b.min(v)));
    }
    drop(g);
    match best {
        Some(v) => ctx.set_return(SyscallReturn::ok(v as u64)),
        None => ctx.set_return(SyscallReturn::ok((-ESRCH) as u64)),
    }
}
