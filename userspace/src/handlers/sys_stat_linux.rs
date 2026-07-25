#[allow(unused_imports)]
use super::*;

#[cfg(feature = "linux-compat")]
pub(crate) fn sys_stat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int stat(const char *pathname, struct stat *statbuf)`.
    // Plain stat always follows a trailing symlink.
    stat_linux_common(ctx, args.arg0, args.arg1, true);
}
