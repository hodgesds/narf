#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_openat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int openat(int dirfd, const char *pathname,
    // int flags, mode_t mode)`. Two-arg path-as-cstr.
    // (Previously arg2 was a NARF-native path_len, which made
    // musl's `openat(AT_FDCWD, "...", O_RDONLY, 0)` hit our
    // handler with arg2 = O_RDONLY = 0 → zero-length path →
    // EINVAL on every open. See [[project_narf_native_vs_linux_abis]].)
    let dirfd = args.arg0 as i64;
    let path_uptr = args.arg1;
    let flags = args.arg2;
    let _mode = args.arg3;
    let path_str = match copy_user_cstr(path_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::ok(!0u64));
            return;
        }
    };
    // Honour a real directory fd: `openat(dirfd, relpath)` resolves `relpath`
    // against the directory backing `dirfd`. Absolute paths and AT_FDCWD
    // resolve as before. sd-device's `chase_symlinks` (behind libudev and
    // elogind's seat-device enumeration) walks a path with one `openat` per
    // component against parent-directory fds; ignoring `dirfd` made every
    // such lookup fail ("Failed to chase symlinks in …") → no DRM card ever
    // attached to a seat. `fd_path_of` returns the dir's chroot-relative path,
    // so joining a relative component and letting `open_impl` re-apply the
    // chroot keeps a chrooted process (e.g. elogind under /mnt) resolving in
    // its own namespace.
    const AT_FDCWD: i64 = -100;
    let effective = if path_str.starts_with('/') || dirfd == AT_FDCWD || dirfd < 0 {
        path_str
    } else {
        match fd_path_for_task(current_task_id(), dirfd as u32) {
            Some(dir) if dir.starts_with('/') => {
                alloc::format!("{}/{}", dir.trim_end_matches('/'), path_str)
            }
            // Unknown / non-directory fd → best-effort cwd-relative resolve.
            _ => path_str,
        }
    };
    // Resolve the `/proc/self/fd/N` (and `/proc/<pid>/fd/N`) magic symlink:
    // opening it reopens the target of fd N. systemd's `fd_reopen` opens an
    // O_PATH handle through `/proc/self/fd/N` to obtain a *readable* fd — and
    // sd-device (libudev) does exactly this for every sysfs `uevent` file: it
    // opens `uevent` O_PATH, verifies the filesystem, then reopens via
    // `/proc/self/fd/N` to read it. Without this the reopen ENOENTs, the uevent
    // read fails EBADF, libudev resolves no devices, and a chrooted compositor
    // (kwin) never finds `/dev/dri/card0`. Linux ref: procfs fd magic symlinks
    // (fs/proc/fd.c) + `fd_reopen` (systemd src/basic/fd-util.c).
    if let Some(n) = parse_proc_self_fd(&effective) {
        let task = current_task_id();
        // Prefer reopening the fd's real backing path with the caller's flags.
        if let Some(p) = fd_path_for_task(task, n).filter(|p| p.starts_with('/')) {
            open_impl(ctx, p, flags, 0, 0);
            return;
        }
        // Pathless fd (memfd, pipe, socket, eventfd) → share its FileOps in a
        // fresh fd, mirroring Linux reopening the same inode/description.
        let dup = fd::with_table(task, |t| t.get(n).map(|e| e.ops.clone())).flatten();
        if let Some(ops) = dup {
            let sf = (flags as u32) & (crate::fd::O_ACCMODE | crate::fd::O_SETFL_MASK);
            let new_fd = fd::with_table(task, |t| {
                t.open(crate::fd::FdEntry {
                    ops,
                    offset: 0,
                    flags: 0,
                    status_flags: sf,
                })
            });
            ctx.set_return(SyscallReturn::ok(
                new_fd.map(|nf| nf as u64).unwrap_or((-1i64) as u64),
            ));
            return;
        }
        // Stale/unknown fd → ENOENT, as Linux does for a dangling fd symlink.
        ctx.set_return(SyscallReturn::ok((-2i64) as u64));
        return;
    }
    open_impl(ctx, effective, flags, 0, 0);
}
