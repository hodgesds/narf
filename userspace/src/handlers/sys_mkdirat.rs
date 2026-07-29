#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_mkdirat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int mkdirat(int dirfd, const char *pathname,
    // mode_t mode)`. arg2 is mode, not path_len.
    let dirfd = args.arg0 as i64;
    let path_uptr = args.arg1;
    let mode = args.arg2;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    let _ = mode;
    const AT_FDCWD: i64 = -100;
    let effective = if path_str.starts_with('/') || dirfd == AT_FDCWD {
        path_str
    } else if dirfd >= 0 {
        match fd_path_for_task(current_task_id(), dirfd as u32) {
            Some(base) if base.starts_with('/') => {
                alloc::format!("{}/{}", base.trim_end_matches('/'), path_str)
            }
            _ => {
                ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
                return;
            }
        }
    } else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    crate::handlers::handler_sys_mkdir::mkdir_path(ctx, &effective);
}
