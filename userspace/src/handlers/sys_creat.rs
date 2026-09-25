#[allow(unused_imports)]
use super::*;

/// `creat(path, mode)` — `fs/open.c`:
///
/// ```text
///   SYSCALL_DEFINE2(creat, const char __user *, pathname, umode_t, mode)
///   { int flags = O_CREAT | O_WRONLY | O_TRUNC;
///     return do_sys_open(AT_FDCWD, pathname, flags, mode); }
/// ```
///
/// Routes straight into [`open_impl`] with the caller's `mode`. The previous
/// reshape into the NARF-native `sys_open` ABI had no mode slot, so every
/// `creat(path, 0600)` created a 0666 & ~umask file — a private file left
/// world-readable.
pub(crate) fn sys_creat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let mode = a.arg1 as u32;
    let path_str = match copy_user_cstr_checked(a.arg0, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    const O_CREAT_WRONLY_TRUNC: u64 = 0o100 | 0o1 | 0o1000;
    open_impl(ctx, path_str, O_CREAT_WRONLY_TRUNC, 0, 0, mode);
}
