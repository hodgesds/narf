#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sethostname(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0;
    let len = args.arg1 as usize;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if len == 0 || len > HOSTNAME_MAX {
        ctx.set_return(fail);
        return;
    }
    let s = match copy_user_path(buf, len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Wave-72: if caller has an explicit UTS NS, write there; else fall
    // through to the global hostname slot.
    #[cfg(feature = "container")]
    {
        let task = current_task_id();
        if let Some(ns) = crate::namespaces::uts_ns_of(task) {
            ns.set_hostname(&s);
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
    }
    let mut g = HOSTNAME.lock();
    g.clear();
    g.push_str(&s);
    ctx.set_return(SyscallReturn::ok(0));
}
