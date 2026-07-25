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
        // Write to the SAME UTS namespace `uname(2)` reads back
        // (`current_uts_ns` — the task's own ns, or the global one when it has
        // none). Using `uts_ns_of` here instead silently dropped the write to
        // the flat `DOMAINNAME` static for any task without an explicit UTS ns,
        // while uname kept reading `global_uts()` → the two never agreed.
        let task = current_task_id();
        crate::namespaces::current_uts_ns(task).set_domainname(&s);
        ctx.set_return(SyscallReturn::ok(0));
    }
    #[cfg(not(feature = "container"))]
    {
        let mut g = DOMAINNAME.lock();
        g.clear();
        g.push_str(&s);
        ctx.set_return(SyscallReturn::ok(0));
    }
}
