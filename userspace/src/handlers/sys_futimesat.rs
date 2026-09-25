#[allow(unused_imports)]
use super::*;

/// `futimesat(dirfd, path, timeval[2])` — x86_64 261 (legacy; glibc's
/// pre-utimensat compat path): `do_futimesat(dfd, filename, utimes)`.
///
/// The `timeval`s are read and range-checked before anything else, and a
/// NULL `path` with a real `dirfd` is the fd form (`do_utimes_fd`), exactly
/// as for `utimensat`.
pub(crate) fn sys_futimesat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    match utimes_read_timeval(a.arg2) {
        Ok(times) => do_utimes(ctx, a.arg0 as i64, a.arg1, times, 0),
        Err(errno) => ctx.set_return(errno_ret(errno)),
    }
}
