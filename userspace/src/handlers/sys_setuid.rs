#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setuid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let uid = ctx.args().arg0 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    // In a non-root user-ns, setuid is only allowed to an id mapped in
    // the ns (Linux EINVAL otherwise). The host root-ns is unrestricted.
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial() && !uns.uid_is_mapped(uid) {
            ctx.set_return(fail);
            return;
        }
    }
    // A (notionally privileged) setuid sets real, effective, and fs uids.
    if write_uidgid(task, |e| {
        e.uid = uid;
        e.euid = uid;
        e.fsuid = uid;
    }) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}
