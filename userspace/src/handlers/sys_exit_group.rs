#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_exit_group(ctx: &mut dyn TrapContext) {
    let tid = current_task_id();
    let pid = task_to_pid_raw(tid).unwrap_or(tid);
    zap_thread_group(tid, pid);
    sys_exit_task(ctx);
}
