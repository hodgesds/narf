#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getppid(ctx: &mut dyn TrapContext) {
    // Fast path: the parent link mirrored onto the current `Task`
    // (`Task::parent_pid`, kept in step with `PARENT_OF` by its writers).
    // One atomic load instead of the `PARENT_OF` spinlock plus two
    // sharded-map lookups. Falls through to the table lookup when the
    // mirror is unfilled (new task, test stub without a `Task`).
    if let Some(ppid) = current_task_ppid_user() {
        ctx.set_return(SyscallReturn::ok(ppid));
        return;
    }
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
    let (ppid, mirror) = if parent_task == 0 {
        (0, 0)
    } else {
        let outer = task_to_pid_raw(parent_task).unwrap_or(parent_task);
        // Report the parent in the CALLER's namespace view — a service's
        // getppid() must see systemd as pid 1, not systemd's outer ProcessId.
        // Identity in the root namespace. The mirror keeps the OUTER pid;
        // the fast path translates it on read.
        (report_pid_to(me, outer), outer)
    };
    // Fill the mirror from this authoritative read so the next call takes
    // the fast path. Compare-exchange from UNMIRRORED only: a concurrent
    // reparent that already mirrored a newer parent must never lose to
    // this (possibly stale) fill.
    crate::task::fill_cached_parent_pid(me, mirror);
    ctx.set_return(SyscallReturn::ok(ppid));
}
