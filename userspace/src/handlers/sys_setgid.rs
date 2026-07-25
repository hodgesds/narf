#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setgid(ctx: &mut dyn TrapContext) {
    let task = current_task_id();
    let gid = ctx.args().arg0 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    #[cfg(feature = "container")]
    {
        let uns = crate::namespaces::current_user_ns(task);
        if !uns.is_initial() && !uns.gid_is_mapped(gid) {
            ctx.set_return(fail);
            return;
        }
    }
    if write_uidgid(task, |e| {
        e.gid = gid;
        e.egid = gid;
        e.fsgid = gid;
    }) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}
