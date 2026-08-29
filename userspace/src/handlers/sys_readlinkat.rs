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
    // `getname_flags` is the first thing every path syscall does, and it has
    // exactly two failures: a pointer it cannot read is -EFAULT, and a path
    // that reaches PATH_MAX with no terminator is -ENAMETOOLONG. This used to
    // answer -1, which reaches libc as EPERM — "operation not permitted" about
    // a caller whose only mistake was a bad pointer.
    let path_str = match copy_user_cstr_checked(path_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    // Honour a real directory fd (see sys_openat): resolve a relative path
    // against the directory backing `dirfd`. chase_symlinks readlinkat()s a
    // component relative to its parent-dir fd.
    const AT_FDCWD: i64 = -100;
    let effective = if path_str.starts_with('/') || dirfd == AT_FDCWD || dirfd < 0 {
        path_str
    } else {
        match fd_path_for_task(current_task_id(), dirfd as u32) {
            Some(dir) if dir.starts_with('/') => {
                alloc::format!("{}/{}", dir.trim_end_matches('/'), path_str)
            }
            _ => path_str,
        }
    };
    readlink_impl(ctx, effective, buf_ptr, buf_len);
}
