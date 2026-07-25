#[allow(unused_imports)]
use super::*;

#[cfg(all(feature = "linux-compat", feature = "container"))]
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
    if !new_root.starts_with('/') || !put_old.starts_with('/') {
        ctx.set_return(fail);
        return;
    }
    // Resolve under the current chroot.
    let new_root_resolved = apply_chroot(&new_root);
    let put_old_resolved = apply_chroot(&put_old);
    // Snapshot the prior root for bind-mounting.
    let task = current_task_id();
    let prior_root = {
        let g = ROOT_DIR_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&task).cloned())
            .unwrap_or_else(|| alloc::string::String::from("/"))
    };
    // new_root must exist under the prior root.
    let new_root_ok = narf_filesystem::registry()
        .resolve_absolute(&new_root_resolved, |_fs, _rel| true)
        .unwrap_or(false);
    if !new_root_ok {
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
