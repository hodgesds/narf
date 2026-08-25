#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_symlink(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux: symlink(const char *target, const char *linkpath). arg0 = target
    // (NUL-term), arg1 = linkpath (NUL-term). (Was NARF-native (target_ptr,
    // target_len, link_ptr, link_len).)
    let target_ptr = args.arg0;
    let link_ptr = args.arg1;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let target_str = match copy_user_cstr(target_ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let link_path = match copy_user_cstr(link_ptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Resolve the link location against the cwd (the symlink *target*
    // stays verbatim — symlink targets may legitimately be relative).
    let link_path = resolve_cwd_path(current_task_id(), &link_path);
    symlink_absolute(ctx, &target_str, &link_path);
}

/// Create a symlink whose LINK PATH is already absolute.
///
/// Split out so `sys_symlinkat` can join its relative linkpath against
/// `newdirfd` and share this body. The target string stays verbatim —
/// symlink targets may legitimately be relative and must not be rewritten.
pub(crate) fn symlink_absolute(ctx: &mut dyn TrapContext, target_str: &str, link_path: &str) {
    let outcome = current_resolve_parent_absolute(link_path, |_fs, parent, leaf| {
        poll_blocking(parent.symlink(leaf, target_str))
    });
    match outcome {
        Some(Some(Ok(_))) => {
            // inotify: a new symlink is IN_CREATE on the link path.
            #[cfg(feature = "linux-compat")]
            crate::mqueue::notify_create(link_path, false);
            ctx.set_return(SyscallReturn::ok(0))
        }
        // An existing link name is EEXIST — systemd-tmpfiles creates symlinks
        // and treats EEXIST as "already present" (idempotent). A read-only
        // backing fs is EROFS. Never a bare -1 → EPERM.
        Some(Some(Err(narf_filesystem::FsError::Busy))) => {
            ctx.set_return(SyscallReturn::ok((-17i64) as u64)) // -EEXIST
        }
        Some(Some(Err(narf_filesystem::FsError::ReadOnly))) => {
            ctx.set_return(SyscallReturn::ok((-30i64) as u64)) // -EROFS
        }
        Some(Some(Err(narf_filesystem::FsError::QuotaExceeded))) => {
            ctx.set_return(SyscallReturn::ok((-122i64) as u64)) // -EDQUOT
        }
        // Parent path/filesystem didn't resolve → a component is missing.
        _ => ctx.set_return(SyscallReturn::ok((-2i64) as u64)), // -ENOENT
    }
}
