#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_mkdirat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int mkdirat(int dirfd, const char *pathname,
    // mode_t mode)`. arg2 is mode, not path_len.
    let dirfd = args.arg0 as i64;
    let path_uptr = args.arg1;
    let mode = args.arg2 as u32;
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
    crate::handlers::handler_sys_mkdir::mkdir_path(ctx, &effective, mode);
}
