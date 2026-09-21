#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_readlinkat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `ssize_t readlinkat(int dirfd, const char *path,
    // char *buf, size_t bufsiz)`.
    let dirfd = args.arg0 as i64;
    let path_uptr = args.arg1;
    let buf_ptr = args.arg2 as *mut u8;
    // `SYSCALL_DEFINE4(readlinkat, ..., int, bufsiz)` — the size is a
    // 32-bit signed int, so the upper half of the register is not part of
    // it and a negative value must stay negative for the -EINVAL gate in
    // `do_readlinkat`.
    let buf_len = args.arg3 as u32 as i32 as i64;
    if buf_len <= 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // `getname_flags` is the first thing every path syscall does, and it has
    // exactly two failures: a pointer it cannot read is -EFAULT, and a path
    // that reaches PATH_MAX with no terminator is -ENAMETOOLONG. This used to
    // answer -1, which reaches libc as EPERM — "operation not permitted" about
    // a caller whose only mistake was a bad pointer.
    let path_str = match copy_user_cstr_checked(path_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if path_str.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    let task = current_task_id();
    let effective = match resolve_at_path(task, dirfd, &path_str) {
        Ok(p) => p,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    readlink_impl(ctx, effective, buf_ptr, buf_len);
}
