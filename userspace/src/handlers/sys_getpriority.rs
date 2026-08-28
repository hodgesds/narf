#[allow(unused_imports)]
use super::*;

/// `kernel/sys.c::SYSCALL_DEFINE2(getpriority, int, which, int, who)`.
///
/// ```text
/// if (which > PRIO_USER || which < PRIO_PROCESS) return -EINVAL;
/// retval = -ESRCH;
/// /* per selected task: */
///     niceval = nice_to_rlimit(task_nice(p));
///     if (niceval > retval) retval = niceval;
/// return retval;
/// ```
///
/// Two things make the return value unusual and both are deliberate:
///
///   * it is `nice_to_rlimit(nice) = 20 - nice`, so a nice of -20..=19 maps
///     to 40..=1 and can never be confused with a negative errno. glibc
///     unwraps it with `20 - ret`.
///   * across a GROUP the answer is the MAXIMUM of that value, i.e. the
///     numerically LOWEST nice — the most favourable process in the set.
///     Taking the minimum, or the first, would report a group as less
///     favoured than it is.
///
/// PRIO_PGRP and PRIO_USER used to take the -EINVAL arm; the selection is
/// now shared with setpriority and the ioprio pair via `resolve_who_targets`.
pub(crate) fn sys_getpriority(ctx: &mut dyn TrapContext) {
    const ESRCH: i64 = 3;
    const EINVAL: i64 = 22;
    const PRIO_PROCESS: i64 = 0;
    const PRIO_PGRP: i64 = 1;
    const PRIO_USER: i64 = 2;
    let args = *ctx.args();
    // `int which`, `int who` — both 32-bit.
    let which = args.arg0 as i32 as i64;
    let who = args.arg1 as i32;
    let scope = match which {
        PRIO_PROCESS => WhoScope::Process,
        PRIO_PGRP => WhoScope::Pgrp,
        PRIO_USER => WhoScope::User,
        _ => {
            ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
            return;
        }
    };
    let targets = resolve_who_targets(scope, who, current_task_id());
    // `retval = -ESRCH` until a task is visited.
    let mut best: Option<i64> = None;
    for t in targets {
        let wire = 20 - i64::from(read_nice(t));
        if best.is_none_or(|b| wire > b) {
            best = Some(wire);
        }
    }
    match best {
        Some(wire) => ctx.set_return(SyscallReturn::ok(wire as u64)),
        None => ctx.set_return(SyscallReturn::ok((-ESRCH) as u64)),
    }
}
