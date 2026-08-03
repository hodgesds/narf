#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_gettid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    // Linux gives a thread-group leader the same numeric identity from
    // gettid() and getpid(). NARF's scheduler TaskId is an internal handle
    // and diverges from the ProcessId after fork; leaking it makes a normal
    // single-threaded child look non-main to systemd's rename_process().
    // `PID_TO_TASK` identifies the group leader, while CLONE_THREAD siblings
    // keep their distinct scheduler id as their thread id.
    ctx.set_return(SyscallReturn::ok(linux_tid_for_task(task)));
}
