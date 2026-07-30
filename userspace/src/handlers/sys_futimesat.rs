#[allow(unused_imports)]
use super::*;

/// `futimesat(dirfd, path, timeval[2])` — x86_64 261 (legacy; glibc's
/// pre-utimensat compat path). Relative paths resolve against the
/// dirfd's recorded open path, same prepend as sys_readlinkat/linkat.
pub(crate) fn sys_futimesat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let raw = match copy_user_cstr(a.arg1, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    const AT_FDCWD: i64 = -100;
    let dirfd = a.arg0 as i64;
    let eff = if raw.starts_with('/') || dirfd == AT_FDCWD || dirfd < 0 {
        raw
    } else {
        match fd_path_for_task(current_task_id(), dirfd as u32) {
            Some(dir) if dir.starts_with('/') => {
                alloc::format!("{}/{}", dir.trim_end_matches('/'), raw)
            }
            _ => raw,
        }
    };
    utimes_common(ctx, &eff, a.arg2);
}
