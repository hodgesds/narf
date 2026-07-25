#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_mkdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_cstr(ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let path = resolve_cwd_path(current_task_id(), &path);
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
    match poll_blocking(parent.mkdir(&leaf)) {
        Some(Ok(_)) => {
            #[cfg(feature = "linux-compat")]
            crate::mqueue::notify_create(&path, true);
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
        _ => ctx.set_return(SyscallReturn::ok((-1i64) as u64)), // -EPERM (fs refused)
    }
}
