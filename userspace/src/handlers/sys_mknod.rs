#[allow(unused_imports)]
use super::*;

/// Linux `mknod(path, mode, dev)` — x86_64 syscall 133. musl's `mknod()`
/// routes here (not through mknodat). path=arg0, mode=arg1, dev=arg2.
pub(crate) fn sys_mknod(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `do_mknodat` runs `may_mknod(mode)` before `filename_create` ever
    // reads the pathname, so a bad node type outranks a bad path pointer.
    if let Err(errno) = may_mknod(args.arg1) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // `getname()`: -EFAULT for an unreadable path, -ENAMETOOLONG for one
    // that reaches PATH_MAX unterminated.
    let raw = match copy_user_cstr_checked(args.arg0, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let ret = mknod_common(&raw, args.arg1, args.arg2);
    ctx.set_return(ret);
}
