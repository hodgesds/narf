#[allow(unused_imports)]
use super::*;

/// `ioprio_set(which, who, ioprio)` — set I/O priority.
/// arg0 = which, arg1 = who (pid), arg2 = ioprio.
/// Returns 0 on success.
pub(crate) fn sys_ioprio_set(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i32;
    let mut who = args.arg1;
    let ioprio = args.arg2 as u32;
    // IOPRIO_WHO_PROCESS's `who` is a pid in the CALLER's pid namespace (Linux
    // block/ioprio.c find_task_by_vpid). Translate inner -> outer so two
    // namespaces with the same inner pid don't share one table entry. Audit
    // finding #23.
    // LINUX-GAP: WHO_PGRP (pgid) / WHO_USER (uid) are keyed untranslated.
    const IOPRIO_WHO_PROCESS: i32 = 1;
    if which == IOPRIO_WHO_PROCESS && who != 0 {
        match accept_pid_from(current_task_id(), who) {
            Some(outer) => who = outer,
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    }
    let mut g = IOPRIO_TABLE.lock();
    let m = g.get_or_insert_with(BTreeMap::new);
    m.insert((which, who), ioprio);
    ctx.set_return(SyscallReturn::ok(0));
}
