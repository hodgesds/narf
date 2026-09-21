#[allow(unused_imports)]
use super::*;

/// `futimesat(dirfd, path, timeval[2])` — x86_64 261 (legacy; glibc's
/// pre-utimensat compat path). Relative paths resolve against the
/// dirfd's recorded open path, same prepend as sys_readlinkat/linkat.
pub(crate) fn sys_futimesat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let raw = match copy_user_cstr_checked(a.arg1, 4096) {
            Ok(s) => s,
            Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
            }
        };
    let dirfd = a.arg0 as i64;
    let task = current_task_id();
    let eff = match resolve_at_path(task, dirfd, &raw) {
        Ok(p) => p,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    utimes_common(ctx, &eff, a.arg2);
}
