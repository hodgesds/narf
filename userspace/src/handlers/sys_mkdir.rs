#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_mkdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    // `getname()` (fs/namei.c): -EFAULT for an unreadable pointer,
    // -ENAMETOOLONG for a path that reaches PATH_MAX with no terminator.
    // Both used to take the shared `fail` sentinel, which reaches libc as
    // errno 1 (EPERM) — an answer that says "you may not do this" about a
    // caller whose only mistake was a bad pointer or an over-long name.
    let path = match copy_user_cstr_checked(ptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    mkdir_path(ctx, &path, args.arg1 as u32);
}

pub(super) fn mkdir_path(ctx: &mut dyn TrapContext, raw_path: &str, mode: u32) {
    if raw_path.is_empty() {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
        return;
    }
    let path = resolve_cwd_path(current_task_id(), raw_path);
    // Normalise trailing slashes; `mkdir("/")` (or any path that resolves
    // to the root) always already exists.
    let path_ref: &str = {
        let t = path.trim_end_matches('/');
        if t.is_empty() {
            "/"
        } else {
            t
        }
    };
    // busybox `mkdir -p` walks each path component, relying on Linux
    // errnos: EEXIST for components that already exist (e.g. `/` and
    // `/run` before `/run/udev`) and ENOENT to trigger recursion on a
    // missing parent. A bare -1 → musl EPERM aborts the whole -p chain.
    if path_ref == "/" {
        ctx.set_return(SyscallReturn::ok((-17i64) as u64)); // -EEXIST (root)
        return;
    }
    // A path that already resolves to a directory exists → EEXIST, matching
    // Linux. This mount-aware check catches a mount root whose parent fs does
    // not expose it as a child entry (e.g. the cgroup2 mount at
    // /sys/fs/cgroup, whose parent /sys/fs is sysfs): the parent-lookup
    // existence check below can't see a mounted-over entry, so mkdir would
    // otherwise try to create it in the parent fs and fail.
    //
    // The second arm treats a path that is an ANCESTOR of an existing
    // mountpoint as an existing directory. In NARF's flat mount model a
    // mount registered at /sys/fs/cgroup has no real intermediate /sys/fs
    // node in sysfs, so `mkdir("/sys/fs")` would try to create it on the
    // read-only sysfs and return a bare -1. systemd's cg_create walks the
    // cgroup hierarchy root via mkdir_parents (mkdir /sys, /sys/fs, …) and
    // treats EEXIST as success; a -1 (→ EPERM) at any component aborts every
    // service's cgroup setup ("Failed to create cgroup /: Operation not
    // permitted").
    if resolve_dir_absolute(path_ref).is_some() || path_is_mount_ancestor(path_ref) {
        ctx.set_return(SyscallReturn::ok((-17i64) as u64)); // -EEXIST
        return;
    }
    let (parent, leaf) = match resolve_parent_dir_async(path_ref) {
        Some(p) => p,
        None => {
            // Parent directory doesn't exist.
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
            return;
        }
    };
    // FsError has no AlreadyExists variant (ext2 maps conflicts to
    // InvalidPath), so detect an existing leaf explicitly for EEXIST.
    let exists = poll_blocking(parent.lookup_async(&leaf))
        .map(|r| r.is_ok())
        .unwrap_or(false)
        || poll_blocking(parent.lookup_dir_async(&leaf))
            .map(|r| r.is_ok())
            .unwrap_or(false);
    if exists {
        ctx.set_return(SyscallReturn::ok((-17i64) as u64)); // -EEXIST
        return;
    }
    // `do_mkdirat` -> `mnt_want_write` -> `filename_create` ->
    // `may_create(dir, ..)`: the mount must be writable, then the caller
    // must have write+exec on the parent.
    if let Err(errno) = mnt_want_write(path_ref) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    if let Err(errno) = may_create_in(&*parent, current_task_id()) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // `fs/namei.c::do_mkdirat` -> `vfs_mkdir` -> `shmem_mkdir` ->
    // `simple_acl_create`: a parent carrying a default ACL passes it down
    // instead of the umask, and a new DIRECTORY also keeps a copy so
    // inheritance continues below it.
    let inherited = inherit_acls_from_parent(&*parent, (mode & 0o1777) as u16, true);
    match poll_blocking(parent.mkdir(&leaf)) {
        Some(Ok(directory)) => {
            {
                // `inode_init_owner`: a setgid parent hands its group to the
                // new directory AND makes the new directory setgid too, which
                // is what keeps a shared group tree shared all the way down.
                let owner_result = poll_blocking(
                    directory.set_dir_owners_async(inherited.uid, inherited.gid),
                );
                let mode_result = poll_blocking(
                    // `vfs_prepare_mode(.., S_IRWXUGO | S_ISVTX, 0)` masks
                    // the CALLER's mode to rwx + sticky, so a caller cannot
                    // ask for setgid — the `& 0o1777` above. S_ISGID on a
                    // new directory comes only from `inode_init_owner`
                    // inheriting it from a setgid parent, which
                    // `inherited.mode` already carries.
                    directory.set_dir_mode_async(inherited.mode),
                );
                // Install the inherited ACLs before anything can observe
                // the directory: an inode that is briefly visible without
                // the ACL it should have been born with is a permission
                // hole, not a cosmetic delay.
                if let Some(blob) = inherited.access.as_ref() {
                    let _ = poll_blocking(directory.set_xattr(
                        narf_filesystem::AclType::Access.xattr_name(),
                        blob,
                        0,
                    ));
                }
                if let Some(blob) = inherited.default.as_ref() {
                    let _ = poll_blocking(directory.set_xattr(
                        narf_filesystem::AclType::Default.xattr_name(),
                        blob,
                        0,
                    ));
                }
                let metadata_error = owner_result
                    .and_then(Result::err)
                    .or_else(|| mode_result.and_then(Result::err));
                if owner_result.is_none() || mode_result.is_none() || metadata_error.is_some() {
                    // Do not report a successful-but-partially-initialized
                    // directory. Best-effort rollback restores the pre-call
                    // namespace when metadata persistence fails.
                    let _ = poll_blocking(parent.rmdir(&leaf));
                    let errno = match metadata_error {
                        Some(narf_filesystem::FsError::PermissionDenied) => -13, // EACCES
                        Some(narf_filesystem::FsError::ReadOnly) => -30,         // EROFS
                        Some(narf_filesystem::FsError::NoSpace) => -28,          // ENOSPC
                        Some(narf_filesystem::FsError::QuotaExceeded) => -122,   // EDQUOT
                        _ => -5,                                                 // EIO
                    };
                    ctx.set_return(SyscallReturn::ok((errno as i64) as u64));
                    return;
                }
                crate::mqueue::notify_create(&path, true);
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        // A racing create of the same leaf → EEXIST (matches the exists check
        // above); a read-only backing fs → EROFS; anything else keeps a
        // precise errno rather than a bare -1 → EPERM (which aborts busybox
        // `mkdir -p` and systemd's cgroup/hierarchy setup).
        Some(Err(narf_filesystem::FsError::Busy)) => {
            ctx.set_return(SyscallReturn::ok((-17i64) as u64)) // -EEXIST
        }
        Some(Err(narf_filesystem::FsError::ReadOnly)) => {
            ctx.set_return(SyscallReturn::ok((-30i64) as u64)) // -EROFS
        }
        Some(Err(narf_filesystem::FsError::NoSpace)) => {
            ctx.set_return(SyscallReturn::ok((-28i64) as u64)) // -ENOSPC
        }
        Some(Err(narf_filesystem::FsError::QuotaExceeded)) => {
            ctx.set_return(SyscallReturn::ok((-122i64) as u64)) // -EDQUOT
        }
        // `vfs_mkdir` opens with `may_create_dentry`, whose permission check
        // is `inode_permission(idmap, dir, MAY_WRITE | MAY_EXEC)` — EACCES,
        // not EPERM, for a parent directory the caller may not write.
        Some(Err(narf_filesystem::FsError::PermissionDenied)) => {
            ctx.set_return(SyscallReturn::ok((-13i64) as u64)) // -EACCES
        }
        Some(Err(narf_filesystem::FsError::NotFound)) => {
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)) // -ENOENT
        }
        Some(Err(narf_filesystem::FsError::Io(_))) => {
            ctx.set_return(SyscallReturn::ok((-5i64) as u64)) // -EIO
        }
        _ => ctx.set_return(SyscallReturn::ok((-1i64) as u64)), // -EPERM (fs refused)
    }
}
