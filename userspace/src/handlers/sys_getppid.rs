#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getppid(ctx: &mut dyn TrapContext) {
    let me = current_task_id();
    // `parent_of` is keyed by the child's VISIBLE pid (ProcessId), which a
    // process fork mints separately from the TaskId (`alloc_pid()` vs the
    // scheduler's TaskId — see `sys_clone`/`sys_fork`, which both
    // `parent_of_set(child_visible_pid, ...)`). Looking up by the raw TaskId
    // missed every forked child, so getppid() returned 0. Translate
    // TaskId → visible pid first (identity when no mapping exists), the same
    // way `sys_getpid` resolves the visible pid.
    let me_pid = task_to_pid_raw(me).unwrap_or(me);
    // `parent_of` stores the parent's TaskId (current_task_id() at fork);
    // translate it to the parent's VISIBLE pid so getppid() agrees with the
    // parent's own getpid() (identity when unregistered).
    let parent_task = parent_of_get(me_pid).unwrap_or(0);
    let ppid = if parent_task == 0 {
        0
    } else {
        let outer = task_to_pid_raw(parent_task).unwrap_or(parent_task);
        // Report the parent in the CALLER's namespace view — a service's
        // getppid() must see systemd as pid 1, not systemd's outer ProcessId.
        // Identity in the root namespace.
        report_pid_to(me, outer)
    };
    ctx.set_return(SyscallReturn::ok(ppid));
}
