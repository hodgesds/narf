#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getpid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    #[cfg(feature = "container")]
    {
        // Wave-67 — translate the outer pid through whichever PID
        // namespace the task belongs to. Root-namespace tasks fall
        // through to the legacy outer == inner path.
        let outer = task_to_pid_raw(task).unwrap_or(task);
        let inner = crate::pid_ns::self_inner_pid(task, outer);
        ctx.set_return(SyscallReturn::ok(inner));
    }
    // Non-container: return the VISIBLE ProcessId, NOT the raw scheduler
    // TaskId. fork()'s return value + waitpid() both speak ProcessId and POSIX
    // requires getpid() to agree (a forked child's getpid() must equal the pid
    // its parent holds). The pgid/sid/tty boundary helpers translate to/from
    // this same visible-pid space. Identity fallback for tasks with no
    // registered pid (early init / kernel-spawned).
    #[cfg(not(feature = "container"))]
    ctx.set_return(SyscallReturn::ok(task_to_pid_raw(task).unwrap_or(task)));
}
