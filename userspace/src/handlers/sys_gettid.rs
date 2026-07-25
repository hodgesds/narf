#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_gettid(ctx: &mut dyn TrapContext) {
    // Returns the scheduler's TaskId for the currently-polling
    // task. With `sys_clone` wired (Syscall::Clone = 56), threads
    // in the same address space observe distinct tids here even
    // though they share `getpid` (when process-group bookkeeping
    // lands; today gettid==getpid since both go through the same
    // task_id_lookup, but `clone` already produces distinct tids).
    ctx.set_return(SyscallReturn::ok(current_task_id()));
}
