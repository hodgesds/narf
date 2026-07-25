#[allow(unused_imports)]
use super::*;

/// `setregid(rgid, egid)`.
pub(crate) fn sys_setregid(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let rgid = a.arg0 as u32;
    let egid = a.arg1 as u32;
    let ok = write_uidgid(current_task_id(), |e| {
        if rgid != u32::MAX {
            e.gid = rgid;
        }
        if egid != u32::MAX {
            e.egid = egid;
            e.fsgid = egid;
        }
    });
    ctx.set_return(SyscallReturn::ok(if ok { 0 } else { (-1i64) as u64 }));
}
