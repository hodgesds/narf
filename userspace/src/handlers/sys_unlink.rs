#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_unlink(ctx: &mut dyn TrapContext) {
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
