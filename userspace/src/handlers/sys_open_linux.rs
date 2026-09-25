#[allow(unused_imports)]
use super::*;

/// Linux ABI variant of `open(2)`: `int open(const char *pathname,
/// int flags, mode_t mode)`. The pathname is already owned after the
/// NUL-terminated user copy, so route it directly into [`open_impl`];
/// reshaping through the native length-bearing handler would copy the same
/// user bytes a second time.
pub(crate) fn sys_open_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_uptr = args.arg0;
    let flags = args.arg1;
    let mode = args.arg2 as u32;
    // `build_open_flags` precedes `getname` (see `open_build_flags`).
    if let Err(errno) = open_build_flags(flags) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    let path_str = match copy_user_cstr_checked(path_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    open_impl(ctx, path_str, flags, 0, 0, mode);
}
