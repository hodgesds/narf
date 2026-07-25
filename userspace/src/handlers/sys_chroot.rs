#[allow(unused_imports)]
use super::*;

#[cfg(feature = "linux-compat")]
pub(crate) fn sys_chroot(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok((-1i64) as u64);
    // Linux `chroot(const char *path)` passes a single NUL-terminated
    // path in arg0 — there is no length argument. (The earlier
    // `copy_user_path_raw(arg0, arg1)` form misread arg1 as a length,
    // which is garbage for a real Linux binary, so every chroot from
    // unmodified userspace failed with -1.)
    let raw = match copy_user_cstr(args.arg0, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if !raw.starts_with('/') {
        ctx.set_return(fail);
        return;
    }
    // Compose against any existing chroot (nested chroot resolves
    // under the current root before installation).
    let resolved = apply_chroot(&raw);
    // Verify resolved exists as a directory under the global
    // registry — match Linux semantics: chroot fails if target
    // doesn't exist. We treat a covering mount as sufficient.
    let covered = narf_filesystem::registry()
        .resolve_absolute(&resolved, |_fs, _rel| true)
        .unwrap_or(false);
    if !covered {
        ctx.set_return(fail);
        return;
    }
    root_dir_init_if_needed();
    let task = current_task_id();
    let mut g = ROOT_DIR_TABLE.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task, resolved);
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}
