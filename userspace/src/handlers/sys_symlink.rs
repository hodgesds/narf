#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_symlink(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux: symlink(const char *target, const char *linkpath). arg0 = target
    // (NUL-term), arg1 = linkpath (NUL-term). (Was NARF-native (target_ptr,
    // target_len, link_ptr, link_len).)
    let target_ptr = args.arg0;
    let link_ptr = args.arg1;
    // `SYSCALL_DEFINE2(symlink)`: `CLASS(filename, old)(oldname)` then
    // `CLASS(filename, new)(newname)`. -EFAULT for an unreadable pointer,
    // -ENAMETOOLONG for a name at PATH_MAX with no terminator — both used
    // to collapse onto the shared `fail` sentinel (libc errno 1, EPERM).
    let target_str = match copy_user_cstr_checked(target_ptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let link_path = match copy_user_cstr_checked(link_ptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if link_path.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
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
    // `do_symlinkat` -> `filename_create` -> `may_create`: write+exec on
    // the directory the link is being added to, checked inside the
    // resolution this already performs.
    if let Err(errno) = mnt_want_write(link_path) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    let task = current_task_id();
    let mut refused = None;
    let outcome = current_resolve_parent_absolute(link_path, |_fs, parent, leaf| {
        if let Err(errno) = may_create_in(&*parent, task) {
            refused = Some(errno);
            return None;
        }
        poll_blocking(parent.symlink(leaf, target_str))
    });
    if let Some(errno) = refused {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    match outcome {
        Some(Some(Ok(_))) => {
            // inotify: a new symlink is IN_CREATE on the link path.
            crate::mqueue::notify_create(link_path, false);
            ctx.set_return(SyscallReturn::ok(0))
        }
        // An existing link name is EEXIST — systemd-tmpfiles creates symlinks
        // and treats EEXIST as "already present" (idempotent). A read-only
        // backing fs is EROFS. Never a bare -1 → EPERM.
        Some(Some(Err(narf_filesystem::FsError::Busy))) => {
            ctx.set_return(errno_ret(EEXIST))
        }
        Some(Some(Err(narf_filesystem::FsError::ReadOnly))) => {
            ctx.set_return(errno_ret(EROFS))
        }
        Some(Some(Err(narf_filesystem::FsError::QuotaExceeded))) => {
            ctx.set_return(errno_ret(EDQUOT))
        }
        // Parent path/filesystem didn't resolve → a component is missing.
        _ => ctx.set_return(errno_ret(ENOENT)),
    }
}
