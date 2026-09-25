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
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if path.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    let last = LastComponent::of(&path);
    let path = resolve_cwd_path(current_task_id(), &path);
    unlink_absolute(ctx, &path, last);
}

/// Unlink a path that is ALREADY resolved to absolute.
///
/// Split out so `sys_unlinkat` can join a relative path against its dirfd
/// and share this body. It previously proxied here with the raw user
/// pointer, which forced the path through `resolve_cwd_path` and discarded
/// the dirfd entirely.
///
/// `last` is the shape of the caller's RAW last component, which the
/// normalised `path` no longer shows.
pub(crate) fn unlink_absolute(ctx: &mut dyn TrapContext, path: &str, last: LastComponent) {
    // `do_unlinkat`: `if (type != LAST_NORM) { error = -EISDIR; goto exit; }`
    // — before `mnt_want_write`. `.`, `..` and `/` always name a directory.
    // Normalising `unlink("d/.")` into `unlink("d")` reached the backend and
    // came back with whatever it reports for a directory victim.
    if !last.is_norm() {
        ctx.set_return(errno_ret(EISDIR));
        return;
    }
    // If this path is a live bound AF_UNIX socket, release its address so it
    // can be re-bound (Linux frees the address when the socket inode is
    // unlinked — dbus/wayland unlink a stale socket before re-binding).
    // Reuse the authoritative parent resolution instead of performing a
    // second complete VFS walk merely to construct the socket key; ordinary
    // regular-file unlinks are the overwhelmingly common case.
    //
    // `do_unlinkat` -> `may_delete(dir, dentry, 0)` runs inside that SAME
    // resolution: write+exec on the parent directory, plus the sticky rule
    // when the parent carries S_ISVTX. `/tmp` is 01777, so this is the
    // check that stops one user removing another user's file there — and
    // nothing checked it before, on any directory. Doing it here rather
    // than through `check_may_delete` keeps unlink at one path walk.
    // `do_unlinkat` -> `mnt_want_write(mnt)`: a read-only mount refuses
    // before any permission question is asked.
    if let Err(errno) = mnt_want_write(path) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // `do_unlinkat`, right after the lookup and before `vfs_unlink` asks
    // any permission question:
    //
    //     if (last.name[last.len]) goto slashes;
    //     ...
    //  slashes:
    //     if (d_is_negative(dentry))  error = -ENOENT;
    //     else if (d_is_dir(dentry))  error = -EISDIR;
    //     else                        error = -ENOTDIR;
    //
    // A trailing slash was normalised away, so `unlink("file/")` used to
    // remove the file.
    if last == LastComponent::NormSlash {
        let errno = match namespace_node_kind(path) {
            None => path_lookup_errno(path),
            Some(true) => EISDIR,
            Some(false) => ENOTDIR,
        };
        ctx.set_return(errno_ret(errno));
        return;
    }
    // `may_delete`: `if (check_sticky(..) || IS_APPEND(inode) ||
    // IS_IMMUTABLE(inode) || ...) return -EPERM;` — an immutable or
    // append-only file cannot be removed, which is what makes `chattr +i`
    // survive an `rm -f` by root.
    if path_inode_flags(path) & narf_filesystem::FS_PRIVILEGED_FL != 0 {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    let task = current_task_id();
    let mut refused = None;
    let outcome = current_resolve_parent_absolute(path, |fs, parent, leaf| {
        if let Some((victim_uid, victim_gid)) = entry_owner(&*parent, leaf) {
            if let Err(errno) = may_delete_in(&*parent, victim_uid, victim_gid, task) {
                refused = Some(errno);
                return (false, None);
            }
        }
        let was_socket = crate::socket::unbind_resolved_path(
            path,
            fs.backing_identity(),
            parent.ino(),
            leaf,
        );
        (was_socket, poll_blocking(parent.unlink(leaf)))
    });
    if let Some(errno) = refused {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    match outcome {
        Some((_, Some(Ok(())))) => {
            crate::mqueue::notify_delete(path, false);
            ctx.set_return(SyscallReturn::ok(0));
        }
        // The address was freed even if no filesystem node backed the path
        // (e.g. the bind's fs couldn't hold a socket inode) — still success.
        Some((true, _)) => ctx.set_return(SyscallReturn::ok(0)),
        // The filesystem resolved the parent but reported an error. Map the
        // common shapes to their Linux errno so a caller can tell an absent
        // name (ENOENT) from a permission or type error — a bare -1 → musl
        // EPERM otherwise (systemd's `rm` of a missing /run path would then
        // look like a spurious permission failure).
        Some((_, Some(Err(e)))) => ctx.set_return(SyscallReturn::ok(unlink_errno(e))),
        // If the filesystem could not complete the unlink, retain the legacy
        // spelling-based socket lookup. Some synthetic filesystems cannot
        // materialise a socket inode even though bind registered its address.
        Some((false, None)) | None if crate::socket::unbind_path(path) => {
            ctx.set_return(SyscallReturn::ok(0));
        }
        // The parent path/filesystem didn't resolve at all → the target
        // can't exist. `link_path_walk` says why: ENOENT for an absent
        // component, ENOTDIR when one is a file (`unlink("f/x")`).
        _ => ctx.set_return(errno_ret(path_lookup_errno(path))),
    }
}
