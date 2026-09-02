#[allow(unused_imports)]
use super::*;

/// Linux `mknodat(dirfd, pathname, mode, dev)` (and `mknod`, which musl
/// routes through mknodat with AT_FDCWD). Creates a filesystem node.
///
/// NARF has no FIFO / socket / character / block node types, so every
/// non-directory node is created as a regular file. That's enough for the
/// callers that matter: elogind/systemd create a per-session `.ref` FIFO
/// (and `/run/systemd/inaccessible/{reg,fifo,sock,chr,blk}` sandbox nodes)
/// and only need the node to EXIST and be openable — without it, elogind's
/// `CreateSession` fails with EINVAL and no logind session is ever created
/// (which a Wayland compositor needs to TakeDevice the GPU). A `S_IFDIR`
/// request is routed to the directory-create path for correctness.
///
/// The `dirfd` is applied to a relative pathname, exactly as `sys_mkdirat`
/// and every other `*at` handler does. It used to be dropped — a relative
/// `mknodat(dirfd, "sock", …)` was resolved against the CWD instead — which
/// silently created the node in the wrong directory. systemd builds its
/// per-boot sandbox nodes `/run/systemd/inaccessible/{reg,chr,blk,fifo,sock}`
/// with exactly that form (`mknodat(fd_of_inaccessible_dir, "sock", …)`),
/// so the nodes never landed under `/run/systemd/inaccessible/`. Every
/// service whose sandbox binds one of them over a path — `ProtectKernelLogs=`
/// (over `/dev/kmsg`), `ProtectClock=`, `ProtectKernelTunables=`, … — then
/// failed its namespace setup with 226/EXIT_NAMESPACE because the bind SOURCE
/// did not exist. On this CachyOS image that is `systemd-logind`,
/// `NetworkManager` and `systemd-resolved` (all set `ProtectKernelLogs=`),
/// i.e. the exact services that gate the seat and the graphical session.
/// (`/inaccessible/dir` was unaffected only because it is made with
/// `mkdirat`, which already honored the dirfd.)
pub(crate) fn sys_mknodat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // mknodat(dirfd, path, mode, dev): dirfd=arg0, path=arg1, mode=arg2, dev=arg3.
    let raw = match copy_user_cstr(args.arg1, 4096) {
        Some(s) => s,
        // `getname()` — an unreadable path is -EFAULT.
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64));
            return;
        }
    };
    // Resolve a relative pathname against the dirfd (absolute paths and
    // AT_FDCWD pass through). EBADF / ENOTDIR come straight back, matching
    // `openat`/`mkdirat`, rather than being resolved against the cwd.
    let path = match resolve_at_path(current_task_id(), args.arg0 as i64, &raw) {
        Ok(p) => p,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    let ret = mknod_common(&path, args.arg2, args.arg3);
    ctx.set_return(ret);
}
