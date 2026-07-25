#[allow(unused_imports)]
use super::*;

/// `link(oldpath, newpath)` — legacy x86_64 86; aarch64 has linkat only.
pub(crate) fn sys_link(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok((-1i64) as u64);
    let (Some(old_raw), Some(new_raw)) = (
        copy_user_cstr(args.arg0, 4096),
        copy_user_cstr(args.arg1, 4096),
    ) else {
        ctx.set_return(fail);
        return;
    };
    link_impl(ctx, &old_raw, &new_raw);
}
