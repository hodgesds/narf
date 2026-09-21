#[allow(unused_imports)]
use super::*;

/// `link(oldpath, newpath)` — legacy x86_64 86; aarch64 has linkat only.
pub(crate) fn sys_link(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `SYSCALL_DEFINE5(linkat)` takes `CLASS(filename, old)(oldname)` then
    // `CLASS(filename, new)(newname)`, and `filename_linkat` propagates the
    // OLD name's error first. The tuple form here evaluated both and then
    // reported one shared sentinel, so which pathname was at fault was lost
    // along with the reason; -EFAULT and -ENAMETOOLONG are now distinct and
    // the old name is answered first, as Linux does.
    let old_raw = match copy_user_cstr_checked(args.arg0, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let new_raw = match copy_user_cstr_checked(args.arg1, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if old_raw.is_empty() || new_raw.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    link_impl(ctx, &old_raw, &new_raw);
}
