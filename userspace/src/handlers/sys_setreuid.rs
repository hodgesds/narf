#[allow(unused_imports)]
use super::*;

/// `setreuid(ruid, euid)` — set the real and/or effective uid; `-1`
/// leaves a field unchanged. The fs uid follows the new effective uid.
pub(crate) fn sys_setreuid(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let ruid = a.arg0 as u32;
    let euid = a.arg1 as u32;
    let ok = write_uidgid(current_task_id(), |e| {
        if ruid != u32::MAX {
            e.uid = ruid;
        }
        if euid != u32::MAX {
            e.euid = euid;
            e.fsuid = euid;
        }
    });
    ctx.set_return(SyscallReturn::ok(if ok { 0 } else { (-1i64) as u64 }));
}
