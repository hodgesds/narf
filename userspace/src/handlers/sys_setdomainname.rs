#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_setdomainname(ctx: &mut dyn TrapContext) {
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
    // If the caller has an explicit UTS namespace, write there; else
    // fall through to the global domainname slot (mirrors sethostname).
    #[cfg(feature = "container")]
    {
        let task = current_task_id();
        if let Some(ns) = crate::namespaces::uts_ns_of(task) {
            ns.set_domainname(&s);
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
    }
    let mut g = DOMAINNAME.lock();
    g.clear();
    g.push_str(&s);
    ctx.set_return(SyscallReturn::ok(0));
}
