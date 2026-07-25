#[allow(unused_imports)]
use super::*;

/// `utimes(path, timeval[2])` — x86_64 235.
pub(crate) fn sys_utimes(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let raw = match copy_user_cstr(a.arg0, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    utimes_common(ctx, &raw, a.arg1);
}
