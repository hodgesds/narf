#[allow(unused_imports)]
use super::*;

/// `getpgrp()` — the calling process's process-group id (legacy; takes
/// no argument, so it always targets self).
pub(crate) fn sys_getpgrp(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(pgid_to_user(
        read_pgid(current_task_id()),
    )));
}
