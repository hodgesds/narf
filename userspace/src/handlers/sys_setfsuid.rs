#[allow(unused_imports)]
use super::*;

/// `setfsuid(fsuid)` — set the filesystem uid and return the PREVIOUS
/// one. Always "succeeds" (the return is the old fsuid, never an errno),
/// matching Linux. `-1` queries without changing.
pub(crate) fn sys_setfsuid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let new = ctx.args().arg0 as u32;
    let old = read_uidgid(task).fsuid;
    if new != u32::MAX {
        let _ = write_uidgid(task, |e| e.fsuid = new);
    }
    ctx.set_return(SyscallReturn::ok(old as u64));
}
