#[allow(unused_imports)]
use super::*;

/// `sethostname(name, len)` — Linux `SYSCALL_DEFINE2(sethostname)`:
///   - `len < 0 || len > __NEW_UTS_LEN(64)` → -EINVAL (a NARF `usize` len can't
///     be negative; `len == 0` is legal and sets an empty hostname),
///   - a faulting `name` → -EFAULT.
///
/// LINUX-GAP: a caller without CAP_SYS_ADMIN in the UTS user-ns is -EPERM
/// before either check; NARF does not model that capability here.
pub(crate) fn sys_sethostname(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let buf = args.arg0;
    let len = args.arg1 as usize;
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
