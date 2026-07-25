#[allow(unused_imports)]
use super::*;

/// `setresgid(rgid, egid, sgid)` — mirror of setresuid for the gid.
pub(crate) fn sys_setresgid(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let new = if a.arg1 as u32 != u32::MAX {
        Some(a.arg1 as u32)
    } else if a.arg0 as u32 != u32::MAX {
        Some(a.arg0 as u32)
    } else {
        None
    };
    if let Some(g) = new {
        let egid = if a.arg1 as u32 != u32::MAX {
            a.arg1 as u32
        } else {
            g
        };
        let _ = write_uidgid(current_task_id(), |e| {
            e.gid = g;
            e.egid = egid;
            e.fsgid = egid;
        });
    }
    ctx.set_return(SyscallReturn::ok(0));
}
