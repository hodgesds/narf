#[allow(unused_imports)]
use super::*;

#[cfg(feature = "linux-compat")]
pub(crate) fn sys_lstat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int lstat(const char *pathname, struct stat *statbuf)`.
    // lstat is stat-that-does-not-follow: describe the symlink itself.
    stat_linux_common(ctx, args.arg0, args.arg1, false);
}
