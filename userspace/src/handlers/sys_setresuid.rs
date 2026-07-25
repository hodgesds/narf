#[allow(unused_imports)]
use super::*;

/// `setresuid(ruid, euid, suid)` — collapse onto NARF's single uid.
/// A `(uid_t)-1` slot means "leave unchanged"; we adopt the effective
/// uid (or the real uid if effective is -1).
pub(crate) fn sys_setresuid(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let new = if a.arg1 as u32 != u32::MAX {
        Some(a.arg1 as u32)
    } else if a.arg0 as u32 != u32::MAX {
        Some(a.arg0 as u32)
    } else {
        None
    };
    if let Some(u) = new {
        // arg1 is the requested euid; set real+effective+fs coherently so
        // a later geteuid/setfsuid sees the change.
        let euid = if a.arg1 as u32 != u32::MAX {
            a.arg1 as u32
        } else {
            u
        };
        let _ = write_uidgid(current_task_id(), |e| {
            e.uid = u;
            e.euid = euid;
            e.fsuid = euid;
        });
    }
    ctx.set_return(SyscallReturn::ok(0));
}
