#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_statfs(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok(!0u64);
    // Linux: statfs(const char *path, struct statfs *buf). arg0 = NUL-term
    // path, arg1 = buf. (Was NARF-native (path_ptr, path_len, buf).)
    let path = match copy_user_cstr(args.arg0, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let buf_ptr = args.arg1;
    if fill_statfs_for_path(&path, buf_ptr) {
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}
