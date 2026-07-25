#[allow(unused_imports)]
use super::*;

/// `setfsgid(fsgid)` — set the filesystem gid, return the previous one.
pub(crate) fn sys_setfsgid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let new = ctx.args().arg0 as u32;
    let old = read_uidgid(task).fsgid;
    if new != u32::MAX {
        let _ = write_uidgid(task, |e| e.fsgid = new);
    }
    ctx.set_return(SyscallReturn::ok(old as u64));
}
