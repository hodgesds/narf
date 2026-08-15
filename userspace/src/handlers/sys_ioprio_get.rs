#[allow(unused_imports)]
use super::*;

/// `ioprio_get(which, who)` — get I/O priority.
/// arg0 = which, arg1 = who (pid).
/// Returns stored priority or Linux default (IOPRIO_CLASS_BE=2 << 13) | 4.
pub(crate) fn sys_ioprio_get(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let which = args.arg0 as i32;
    let mut who = args.arg1;
    // IOPRIO_WHO_PROCESS's `who` is a pid in the CALLER's pid namespace (Linux
    // block/ioprio.c). Translate inner -> outer before the lookup so it reads
    // the caller-namespace task's entry, not a same-numbered host task's. Audit
    // finding #23.
    // LINUX-GAP: WHO_PGRP (pgid) / WHO_USER (uid) are looked up untranslated.
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
    let g = IOPRIO_TABLE.lock();
    let result = g
        .as_ref()
        .and_then(|m| m.get(&(which, who)).copied())
        .unwrap_or((2u32 << 13) | 4); // IOPRIO_CLASS_BE=2 (bits 13-15), prio=4
    ctx.set_return(SyscallReturn::ok(result as u64));
}
