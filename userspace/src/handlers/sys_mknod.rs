#[allow(unused_imports)]
use super::*;

/// Linux `mknod(path, mode, dev)` — x86_64 syscall 133. musl's `mknod()`
/// routes here (not through mknodat). path=arg0, mode=arg1, dev=arg2.
pub(crate) fn sys_mknod(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `getname()` — an unreadable path is -EFAULT.
    let raw = match copy_user_cstr(args.arg0, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    let ret = mknod_common(&raw, args.arg1, args.arg2);
    ctx.set_return(ret);
}
