#[allow(unused_imports)]
use super::*;

/// `truncate(path, length)` with `fs/open.c::do_sys_truncate` /
/// `vfs_truncate` errno shape and ORDER:
///
/// ```text
///   if (length < 0) return -EINVAL;
///   error = user_path_at(...);          /* -EFAULT/-ENOENT/-ENOTDIR/-EACCES/-ELOOP */
///   if (S_ISDIR(inode->i_mode))  return -EISDIR;
///   if (!S_ISREG(inode->i_mode)) return -EINVAL;
///   error = mnt_want_write(path->mnt);                      /* -EROFS  */
///   error = inode_permission(idmap, inode, MAY_WRITE);      /* -EPERM (immutable) / -EACCES */
///   if (IS_APPEND(inode)) goto out;                         /* -EPERM  */
///   error = get_write_access(inode);                        /* -ETXTBSY */
///   ... do_truncate()
/// ```
///
/// Every one of those used to be the `-1` sentinel, which userspace decodes
/// as EPERM. `truncate("/does/not/exist", 0)` reporting "Operation not
/// permitted" instead of ENOENT defeats the standard create-if-missing
/// fallback, so each case now carries its own errno. The read-only-mount
/// check used to run before the lookup, so a missing path or a directory on
/// a read-only mount answered EROFS where Linux names the path problem.
pub(crate) fn sys_truncate(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux: truncate(const char *path, off_t length). arg0 = NUL-terminated
    // path, arg1 = new length. (Was NARF-native (path_ptr, path_len, size).)
    let ptr = args.arg0;
    let new_size = args.arg1;

    if (new_size as i64) < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let raw = match copy_user_cstr_checked(ptr, 4096) {
        Ok(p) => p,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let task = current_task_id();
    // `user_path_at(AT_FDCWD, pathname, LOOKUP_FOLLOW, &path)`. Relative
    // names resolve against the cwd (they used to reach the resolver
    // unanchored and always miss with ENOENT).
    let found = match user_path_lookup(task, -100, &raw, true, false) {
        Ok(found) => found,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // A directory is EISDIR; any other non-regular target (fifo, socket,
    // device node) is EINVAL — truncation is only defined for regular files.
    match found.stat.mode.file_type {
        narf_filesystem::FileType::File => {}
        narf_filesystem::FileType::Dir => {
            ctx.set_return(errno_ret(EISDIR));
            return;
        }
        _ => {
            ctx.set_return(errno_ret(EINVAL));
            return;
        }
    }
    let path = found.path;
    // `vfs_truncate` -> `mnt_want_write`: changing a file's length is a
    // write, refused with EROFS on a read-only mount.
    if mnt_want_write(&path).is_err() {
        ctx.set_return(errno_ret(EROFS));
        return;
    }
    let Some(ops) = resolve_file_absolute_ext(&path, true) else {
        ctx.set_return(errno_ret(ENOENT));
        return;
    };
    let iflags = ops.inode_flags();
    // `inode_permission(MAY_WRITE)`: "Nobody gets write access to an
    // immutable file" (-EPERM, even for root) before the DAC check.
    if iflags & narf_filesystem::FS_IMMUTABLE_FL != 0 {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    // ...then the DAC/ACL check proper: truncate(2) by path needs write
    // permission on the file, exactly as opening it O_WRONLY would.
    let stat = ops.stat();
    let (uid, gid) = ops.owners();
    if let Err(errno) = node_permission(
        task,
        Some(ops.as_ref()),
        stat.mode.perms,
        uid,
        gid,
        false,
        narf_filesystem::AccessRequest {
            read: false,
            write: true,
            exec: false,
        },
    ) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    // `if (IS_APPEND(inode)) goto mnt_drop_write_and_out;` — -EPERM.
    if immutable_check(iflags, true, false).is_err() {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    // `notify_change` -> `inode_newsize_ok`: RLIMIT_FSIZE bounds a truncate
    // that GROWS the file. Ahead of `file_remove_privs` for the same reason
    // the write path is — a resize refused with -EFBIG must not strip the
    // set-user-ID bit on its way out.
    if let Err(errno) = fsize_check_resize(task, stat.size, new_size) {
        ctx.set_return(errno_ret(errno));
        return;
    }
    // `do_truncate` passes `ATTR_KILL_SUID | ATTR_KILL_SGID` alongside the
    // size change, for the same reason a write does.
    file_remove_privs(ops.as_ref(), task);
    match poll_blocking(ops.truncate(new_size)) {
        Some(Ok(())) => {
            // inotify: truncate changes file content → IN_MODIFY.
            crate::mqueue::notify_modify_path(&path);
            ctx.set_return(SyscallReturn::ok(0));
        }
        Some(Err(error)) => ctx.set_return(errno_ret(copy_fs_errno(error))),
        None => ctx.set_return(errno_ret(EIO)),
    }
}
