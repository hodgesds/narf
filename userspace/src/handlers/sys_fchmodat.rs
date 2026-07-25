#[allow(unused_imports)]
use super::*;

/// `fchmodat(dirfd, path, mode, flags)` / `fchmodat2(..., flags)`.
/// Split from `sys_fchmodat_or_fchownat` because a chmod's `arg2` is a
/// MODE (a chown's is a uid) — and a directory's mode is observable via
/// `stat`, which dbus/systemd read to reject a group/other-writable
/// `XDG_RUNTIME_DIR`. So `chmod 0700` on a tmpfs dir must actually take.
/// musl implements `chmod(2)` as `fchmodat(AT_FDCWD, path, mode, 0)`, so
/// every libc chmod lands here. Files keep the accept-and-ignore
/// behaviour (NARF has no per-file mode enforcement).
pub(crate) fn sys_fchmodat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_uptr = args.arg1;
    let raw = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            // Unreadable user path pointer → EFAULT, not a bare -1 → EPERM.
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    let path = resolve_cwd_path(current_task_id(), &raw);
    if let Some(dir) = resolve_dir_absolute(&path) {
        dir.set_dir_mode((args.arg2 as u32 & 0o7777) as u16);
        // inotify: a mode change is IN_ATTRIB on the affected directory.
        #[cfg(feature = "linux-compat")]
        crate::mqueue::notify_attrib(&path, true);
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // A regular file: persist the mode through FileOps::set_perms so a later
    // stat reflects it (systemd-tmpfiles `z`/`Z` lines chmod files and then
    // verify the mode took). Fall back to accept-and-ignore for synthetic
    // filesystems whose nodes don't hold perms.
    let file = narf_filesystem::registry().resolve_absolute(&path, |fs, rel| {
        narf_filesystem::resolve(fs.root(), rel).ok()
    });
    if let Some(Some(file)) = file {
        let _ = poll_blocking(file.set_perms((args.arg2 as u32 & 0o777) as u16));
        // inotify: IN_ATTRIB for a chmod on an existing file.
        #[cfg(feature = "linux-compat")]
        crate::mqueue::notify_attrib(&path, false);
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if stat_path_dir_aware(&path).is_some() {
        // inotify: IN_ATTRIB for a chmod on an existing node (synthetic fs).
        #[cfg(feature = "linux-compat")]
        crate::mqueue::notify_attrib(&path, false);
        ctx.set_return(SyscallReturn::ok(0));
    } else {
        // Nothing at this path → ENOENT (was a bare -1 → EPERM).
        ctx.set_return(SyscallReturn::ok((-2i64) as u64));
    }
}
