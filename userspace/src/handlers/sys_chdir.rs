#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_chdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    // Linux ABI: `int chdir(const char *path)` — a single NUL-terminated
    // path, no length arg. (Previously this read arg1 as a NARF-native
    // length, so musl/busybox's chdir(path) hit us with garbage in arg1
    // and failed every cd. Same fix as openat — see
    // [[narf-mmap-no-file-backed]] / the *at ABI cutover.)
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_cstr(ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let task = current_task_id();
    // Validate against the chroot-resolved path, but STORE the user
    // view — chroot is applied exactly once, at resolution time (see
    // resolve_cwd_path_user).
    let user_abs = resolve_cwd_path_user(task, &path);
    let abs = resolve_cwd_path(task, &path);
    // Linux chdir(2) follows the final symlink.  The directory walker below
    // deliberately accepts directories only, so expand links first instead
    // of rejecting a valid link-to-directory (Fedora's
    // /usr/share/X11/xkb -> ../xkeyboard-config-2 is one such path).
    let Some(resolved) = resolve_vfs_symlink_path(&abs, true) else {
        ctx.set_return(fail);
        return;
    };
    // Reject cd into a path that isn't a directory (ENOENT/ENOTDIR).
    if resolve_dir_absolute(&resolved).is_none() {
        ctx.set_return(fail);
        return;
    }
    let mut g = CWD_TABLE.lock();
    let map = match g.as_mut() {
        Some(m) => m,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    map.insert(task, user_abs);
    ctx.set_return(SyscallReturn::ok(0));
}
