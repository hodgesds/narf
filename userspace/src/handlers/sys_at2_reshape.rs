#[allow(unused_imports)]
use super::*;

/// `faccessat2(dirfd, path, mode, flags)` / `fchmodat2(dirfd, path, mode,
/// flags)` — both reshape the Linux NUL-terminated `path` into the NARF
/// `(dirfd, path_ptr, path_len)` shape and forward to the shared
/// existence-checking handler (mode/flags are accepted but not enforced).
pub(crate) fn sys_at2_reshape(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let path_len = match copy_user_cstr(a.arg1, 4096) {
        Some(s) => s.len(),
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    let proxy_args = SyscallArgs {
        arg0: a.arg0, // dirfd
        arg1: a.arg1, // path ptr
        arg2: path_len as u64,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = ArgReshape {
        inner: ctx,
        args: proxy_args,
    };
    sys_fchmodat_or_fchownat(&mut proxy);
}
