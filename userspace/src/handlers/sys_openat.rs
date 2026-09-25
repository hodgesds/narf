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
    let mode = args.arg3 as u32;
    // `do_sys_openat2` runs `build_open_flags` before `getname`: an invalid
    // flag combination is -EINVAL even with an unreadable pathname.
    if let Err(errno) = open_build_flags(flags) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    let path_str = match copy_user_cstr_checked(path_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno)); // -EFAULT
            return;
        }
    };
    if path_str.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    let task = current_task_id();
    // A detached mount returned by fsmount(2) is a directory fd even
    // though it intentionally has no pathname.  systemd's credential
    // setup reopens it with `openat(mfd, ".", O_DIRECTORY|O_CLOEXEC)`
    // before populating and attaching the credentials tmpfs.  Routing
    // every relative dirfd through fd_path_for_task rejected that valid
    // operation as EBADF because detached mounts are pathless.
    //
    // Do not generalize this to arbitrary pathless descriptors: a pipe,
    // socket, or fs-context is not a directory.  A MountObjectFile is
    // explicitly directory-typed and may be reopened as a new reference
    // to the same detached mount, exactly like Linux's fd_reopen helper.
    if dirfd >= 0 && path_str == "." {
        let mount = fd::with_table(task, |t| {
            t.get(dirfd as u32)
                .and_then(|entry| entry.ops.mount_object_id().map(|_| entry.ops.clone()))
        })
        .flatten();
        if let Some(ops) = mount {
            let status_flags =
                (flags as u32) & (crate::fd::O_ACCMODE | crate::fd::O_SETFL_MASK);
            let fd_flags = if flags & crate::fd::O_CLOEXEC as u64 != 0 {
                crate::fd::FD_CLOEXEC
            } else {
                0
            };
            let reopened = fd::install(task, crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: fd_flags,
                status_flags,
            });
            ctx.set_return(SyscallReturn::ok(
                reopened.map(|fd| fd as u64).unwrap_or((-EMFILE) as u64),
            ));
            return;
        }
    }
    // Honour a real directory fd: `openat(dirfd, relpath)` resolves `relpath`
    // against the directory backing `dirfd`. Absolute paths and AT_FDCWD
    // resolve as before. sd-device's `chase_symlinks` (behind libudev and
    // elogind's seat-device enumeration) walks a path with one `openat` per
    // component against parent-directory fds; ignoring `dirfd` made every
    // such lookup fail ("Failed to chase symlinks in …") → no DRM card ever
    // attached to a seat. `resolve_at_path` verifies `dirfd` is a valid
    // directory descriptor (returning -ENOTDIR if not, and -EBADF if invalid),
    // matching Linux path_init / do_sys_openat2 (fs/namei.c:2750-2755).
    let effective = match resolve_at_path(task, dirfd, &path_str) {
        Ok(path) => path,
        Err(errno) => {
            // `FD_ADD` reserves the descriptor before `path_init` looks at
            // `dirfd`, so a full table is -EMFILE ahead of -EBADF/-ENOTDIR.
            if !fd::has_free_descriptor(task) {
                ctx.set_return(errno_ret(EMFILE));
                return;
            }
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
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
            open_impl(ctx, p, flags, 0, 0, mode);
            return;
        }
        // Pathless fd (memfd, pipe, socket, eventfd) → share its FileOps in a
        // fresh fd, mirroring Linux reopening the same inode/description.
        let dup = fd::with_table(task, |t| t.get(n).map(|e| e.ops.clone())).flatten();
        if let Some(ops) = dup {
            let sf = (flags as u32) & (crate::fd::O_ACCMODE | crate::fd::O_SETFL_MASK);
            let new_fd = fd::install(task, crate::fd::FdEntry {
                    ops,
                    offset: 0,
                    flags: 0,
                    status_flags: sf,
                });
            ctx.set_return(SyscallReturn::ok(
                new_fd.map(|nf| nf as u64).unwrap_or((-EMFILE) as u64),
            ));
            return;
        }
        // Stale/unknown fd → ENOENT, as Linux does for a dangling fd symlink.
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    open_impl(ctx, effective, flags, 0, 0, mode);
}

/// Re-enter `openat` with the pathname and directory fd from `ctx`, but a
/// caller-selected flags word.  `open_tree(2)` uses this to implement Linux's
/// non-cloning O_PATH form without exposing the legacy NARF `open` ABI.
pub(crate) fn sys_openat_with_flags(ctx: &mut dyn TrapContext, flags: u64) {
    let args = *ctx.args();
    let proxy_args = SyscallArgs {
        arg0: args.arg0,
        arg1: args.arg1,
        arg2: flags,
        arg3: 0,
        arg4: 0,
        arg5: 0,
    };
    let mut proxy = ReshapeArgs {
        inner: ctx,
        args: proxy_args,
    };
    sys_openat(&mut proxy);
}
