#[allow(unused_imports)]
use super::*;

#[cfg(feature = "linux-compat")]
pub(crate) fn sys_pivot_root(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fail = SyscallReturn::ok((-1i64) as u64);
    // Linux ABI: pivot_root(const char *new_root, const char *put_old).
    // Both arguments are NUL-terminated strings; there are no explicit
    // lengths. The old NARF-native four-argument decoder retained the
    // terminator in the stored root and consumed the put_old pointer as a
    // length, so successful calls installed a path such as "/new_root\0".
    let new_root = match copy_user_cstr(args.arg0, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let put_old = match copy_user_cstr(args.arg1, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // new_root / put_old are resolved against the caller's cwd like any path
    // argument. The canonical container idiom is
    // `fchdir(new_root_fd); pivot_root(".", ".")` — systemd's
    // mount_switch_root_pivot (and runc, etc.) do exactly this — so RELATIVE
    // paths, notably ".", must resolve against the cwd rather than be rejected.
    // Rejecting non-absolute paths made systemd-udevd's PrivateMounts=yes
    // sandbox fail with 226/EXIT_NAMESPACE and restart-loop, wedging boot.
    // resolve_cwd_path resolves against the cwd and re-roots under any active
    // chroot, so absolute paths keep their prior meaning.
    let task = current_task_id();
    let new_root_resolved = resolve_cwd_path(task, &new_root);
    let put_old_resolved = resolve_cwd_path(task, &put_old);
    let prior_root = {
        let g = ROOT_DIR_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&task).cloned())
            .unwrap_or_else(|| alloc::string::String::from("/"))
    };
    // new_root must resolve to an EXISTING DIRECTORY. Use `resolve_dir_absolute`,
    // not `resolve_absolute(|_,_| true)`: the latter matches the root `/` mount
    // as a fallback for ANY absolute path, so a non-existent new_root
    // (e.g. `pivot_root("/nonexistent", ...)`) would bogusly pass the check,
    // succeed, and install a garbage task root — corrupting every later path
    // lookup for the task. Linux returns ENOTDIR/ENOENT here.
    if resolve_dir_absolute(&new_root_resolved).is_none() {
        ctx.set_return(fail);
        return;
    }
    // Bind-mount prior_root at put_old_resolved so the old root is
    // still reachable from inside the new root.
    let auth = narf_filesystem::bootstrap_mount_authority();
    let _ = narf_filesystem::registry().bind_mount(&auth, &prior_root, &put_old_resolved);
    // Install the new root.
    root_dir_init_if_needed();
    let mut g = ROOT_DIR_TABLE.lock();
    if let Some(m) = g.as_mut() {
        m.insert(task, new_root_resolved);
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        ctx.set_return(fail);
    }
}
