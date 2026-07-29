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
    let tid = match task_to_pid_raw(task) {
        Some(pid) if pid_to_task_raw(pid) == Some(task) => {
            #[cfg(feature = "container")]
            {
                crate::pid_ns::self_inner_pid(task, pid)
            }
            #[cfg(not(feature = "container"))]
            {
                pid
            }
        }
        _ => task,
    };
    ctx.set_return(SyscallReturn::ok(tid));
}
