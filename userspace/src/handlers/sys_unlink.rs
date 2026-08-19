#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_unlink(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0;
    // POSIX-shaped failure sentinel. The kernel's syscall ABI carries
    // a separate `status` field but the user-runtime asm wrapper only
    // observes the `value` register; we mirror libc and return -1 on
    // failure so the caller can distinguish from a success return of 0.
    let fail = SyscallReturn::ok((-1i64) as u64);
    let path = match copy_user_cstr(ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let path = resolve_cwd_path(current_task_id(), &path);
    unlink_absolute(ctx, &path);
}

/// Unlink a path that is ALREADY resolved to absolute.
///
/// Split out so `sys_unlinkat` can join a relative path against its dirfd
/// and share this body. It previously proxied here with the raw user
/// pointer, which forced the path through `resolve_cwd_path` and discarded
/// the dirfd entirely.
pub(crate) fn unlink_absolute(ctx: &mut dyn TrapContext, path: &str) {
    let fail = SyscallReturn::ok((-1i64) as u64);
    let _ = fail;
    // If this path is a live bound AF_UNIX socket, release its address so
    // it can be re-bound (Linux frees the address when the socket inode is
    // unlinked — dbus/wayland unlink a stale socket before re-binding).
    let was_socket = crate::socket::unbind_path(path);
    let outcome = current_resolve_parent_absolute(path, |_fs, parent, leaf| {
            poll_blocking(parent.unlink(leaf))
        });
    match outcome {
        Some(Some(Ok(()))) => {
            #[cfg(feature = "linux-compat")]
            crate::mqueue::notify_delete(path, false);
            ctx.set_return(SyscallReturn::ok(0));
        }
        // The address was freed even if no filesystem node backed the path
        // (e.g. the bind's fs couldn't hold a socket inode) — still success.
        _ if was_socket => ctx.set_return(SyscallReturn::ok(0)),
        // The filesystem resolved the parent but reported an error. Map the
        // common shapes to their Linux errno so a caller can tell an absent
        // name (ENOENT) from a permission or type error — a bare -1 → musl
        // EPERM otherwise (systemd's `rm` of a missing /run path would then
        // look like a spurious permission failure).
        Some(Some(Err(e))) => ctx.set_return(SyscallReturn::ok(unlink_errno(e))),
        // The parent path/filesystem didn't resolve at all → the target
        // can't exist. Linux returns ENOENT when a path component is absent.
        _ => ctx.set_return(SyscallReturn::ok((-2i64) as u64)), // -ENOENT
    }
}
