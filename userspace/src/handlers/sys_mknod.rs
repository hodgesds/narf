#[allow(unused_imports)]
use super::*;

/// Linux `mknod(path, mode, dev)` — x86_64 syscall 133. musl's `mknod()`
/// routes here (not through mknodat). path=arg0, mode=arg1, dev=arg2.
pub(crate) fn sys_mknod(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ret = mknod_common(args.arg0, args.arg1, args.arg2);
    ctx.set_return(ret);
}
