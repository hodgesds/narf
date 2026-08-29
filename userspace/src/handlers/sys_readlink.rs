#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_readlink(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `ssize_t readlink(const char *pathname, char *buf,
    // size_t bufsiz)`. arg1 is buf, arg2 is bufsiz. The previous
    // NARF-native shape used arg1 as path_len.
    let path_ptr = args.arg0;
    let buf_ptr = args.arg1 as *mut u8;
    // `SYSCALL_DEFINE4(readlinkat, ..., int, bufsiz)` — the size is a
    // 32-bit signed int, so the upper half of the register is not part of
    // it and a negative value must stay negative for the -EINVAL gate in
    // `do_readlinkat`.
    let buf_len = args.arg2 as u32 as i32 as i64;
    // `getname_flags` is the first thing every path syscall does, and it has
    // exactly two failures: a pointer it cannot read is -EFAULT, and a path
    // that reaches PATH_MAX with no terminator is -ENAMETOOLONG. This used to
    // answer -1, which reaches libc as EPERM — "operation not permitted" about
    // a caller whose only mistake was a bad pointer.
    let raw = match copy_user_cstr_checked(path_ptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    readlink_impl(ctx, raw, buf_ptr, buf_len);
}
