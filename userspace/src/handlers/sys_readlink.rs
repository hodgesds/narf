#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_readlink(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `ssize_t readlink(const char *pathname, char *buf,
    // size_t bufsiz)`. arg1 is buf, arg2 is bufsiz. The previous
    // NARF-native shape used arg1 as path_len.
    let path_ptr = args.arg0;
    let buf_ptr = args.arg1 as *mut u8;
    let buf_len = args.arg2 as usize;
    let raw = match copy_user_cstr(path_ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    readlink_impl(ctx, raw, buf_ptr, buf_len);
}
