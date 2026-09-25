#[allow(unused_imports)]
use super::*;

/// `utimes(path, timeval[2])` — x86_64 235:
/// `do_futimesat(AT_FDCWD, filename, utimes)`.
pub(crate) fn sys_utimes(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    match utimes_read_timeval(a.arg1) {
        Ok(times) => do_utimes(ctx, -100, a.arg0, times, 0),
        Err(errno) => ctx.set_return(errno_ret(errno)),
    }
}
