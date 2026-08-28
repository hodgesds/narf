#[allow(unused_imports)]
use super::*;

/// `sethostname(name, len)` — Linux `SYSCALL_DEFINE2(sethostname)`:
///   - `len < 0 || len > __NEW_UTS_LEN(64)` → -EINVAL (a NARF `usize` len can't
///     be negative; `len == 0` is legal and sets an empty hostname),
///   - a faulting `name` → -EFAULT.
///
/// The capability check comes FIRST in Linux, before the length and the
/// copy: `if (!ns_capable(...uts_ns->user_ns, CAP_SYS_ADMIN)) return -EPERM;`
/// So an unprivileged caller gets -EPERM even when its length is also
/// invalid and its buffer also faults — it learns nothing about either.
///
/// The check is per-UTS-namespace — `ns_capable(uts_ns->user_ns,
/// CAP_SYS_ADMIN)`, not `capable()`. Consulting the host effective set
/// instead refused the owner of a user namespace inside its OWN UTS
/// namespace, so `unshare -Ur --uts hostname foo` (what every rootless
/// container runtime does at startup) came back -EPERM even though the
/// hostname it wanted to set is visible to nobody else.
pub(crate) fn sys_sethostname(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0;
    let len = args.arg1 as usize;
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
