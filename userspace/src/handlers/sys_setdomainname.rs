#[allow(unused_imports)]
use super::*;

/// `setdomainname(name, len)` — Linux `SYSCALL_DEFINE2(setdomainname)`, mirror
/// of sethostname:
///   - `len < 0 || len > __NEW_UTS_LEN(64)` → -EINVAL (`len == 0` sets empty),
///   - a faulting `name` → -EFAULT.
///
/// As in sethostname, `if (!ns_capable(..., CAP_SYS_ADMIN)) return -EPERM;`
/// runs before the length check and the copy.
pub(crate) fn sys_setdomainname(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0;
    let len = args.arg1 as usize;
    // Same per-UTS-namespace rule as `sethostname`:
    // `ns_capable(current->nsproxy->uts_ns->user_ns, CAP_SYS_ADMIN)`.
    if !uts_admin(current_task_id()) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
        return;
    }
    if len > HOSTNAME_MAX {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let s = if len == 0 {
        alloc::string::String::new()
    } else {
        match copy_user_path(buf, len) {
            Some(s) => s,
            None => {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
                return;
            }
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
