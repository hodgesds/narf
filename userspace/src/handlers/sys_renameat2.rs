#[allow(unused_imports)]
use super::*;

/// `renameat2(olddirfd, old, newdirfd, new, flags)` — rename with
/// RENAME_NOREPLACE (fail if the destination exists). RENAME_EXCHANGE
/// and RENAME_WHITEOUT aren't supported (EINVAL).
///
/// Both dirfds are honoured. They were previously treated as AT_FDCWD, which
/// silently resolved a relative path against the CWD — the same defect
/// `sys_renameat` had, and worse than an error: with a same-named file under
/// the cwd it renames the WRONG file and reports success. glibc implements
/// plain `rename(2)` on top of renameat2, so this is the path a distro libc
/// actually takes.
pub(crate) fn sys_renameat2(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let old_uptr = args.arg1;
    let new_uptr = args.arg3;
    let flags = args.arg4 as u32;
    let old_path = match copy_user_cstr_checked(old_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let new_path = match copy_user_cstr_checked(new_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    const RENAME_NOREPLACE: u32 = 1;
    const RENAME_EXCHANGE: u32 = 2;
    const RENAME_WHITEOUT: u32 = 4;
    // A bare -1 lands in glibc's [-4095,-1] errno window as EPERM, which
    // reads as a permission problem; return real errnos instead.
    let einval = errno_ret(EINVAL);
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
        || ((flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0) && (flags & RENAME_EXCHANGE != 0))
    {
        ctx.set_return(einval);
        return;
    }
    if flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
        // RENAME_EXCHANGE and RENAME_WHITEOUT are not supported (EINVAL)
        ctx.set_return(einval);
        return;
    }
    if old_path.is_empty() || new_path.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    // glibc implements plain `rename(2)` on top of renameat2, so this is
    // the path a distro's libc actually takes — it has to resolve
    // relative paths against the cwd exactly like `sys_rename` does.
    let task = current_task_id();
    let old_path = match resolve_at_path(task, args.arg0 as i64, &old_path) {
        Ok(p) => p,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok(e as u64));
            return;
        }
    };
    let new_path = match resolve_at_path(task, args.arg2 as i64, &new_path) {
        Ok(p) => p,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok(e as u64));
            return;
        }
    };
    let old_path = resolve_cwd_path(task, &old_path);
    let new_path = resolve_cwd_path(task, &new_path);
    let old_split = match old_path.rfind('/') {
        Some(i) => i,
        None => {
            ctx.set_return(einval);
            return;
        }
    };
    let new_split = match new_path.rfind('/') {
        Some(i) => i,
        None => {
            ctx.set_return(einval);
            return;
        }
    };
    let new_leaf = &new_path[new_split + 1..];
    if flags & RENAME_NOREPLACE != 0 {
        let exists = current_resolve_parent_absolute(&new_path, |_fs, parent, leaf| {
            parent.lookup(leaf).is_some()
        })
        .unwrap_or(false);
        if exists {
            ctx.set_return(errno_ret(EEXIST));
            return;
        }
    }
    // Different parent directories: a move within one mount, not
    // automatically EXDEV. See `cross_dir_rename`.
    if old_path[..old_split] != new_path[..new_split] {
        ctx.set_return(SyscallReturn::ok(cross_dir_rename(&old_path, &new_path)));
        return;
    }
    // Same `may_delete` pair `rename_absolute` makes, and for the same
    // reason: RENAME_EXCHANGE swaps two names, so both are victims. The
    // check rides the resolution this already does.
    if let Err(errno) = mnt_want_write(&old_path).and_then(|()| mnt_want_write(&new_path)) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    if path_inode_flags(&old_path) & narf_filesystem::FS_PRIVILEGED_FL != 0
        || path_inode_flags(&new_path) & narf_filesystem::FS_PRIVILEGED_FL != 0
    {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    let perm_task = current_task_id();
    let mut refused = None;
    let outcome = current_resolve_parent_absolute(&old_path, |_fs, parent, old_leaf| {
        for leaf in [old_leaf, new_leaf] {
            if let Some((victim_uid, victim_gid)) = entry_owner(&*parent, leaf) {
                if let Err(errno) = may_delete_in(&*parent, victim_uid, victim_gid, perm_task) {
                    refused = Some(errno);
                    return None;
                }
            }
        }
        poll_blocking(parent.rename(old_leaf, new_leaf))
    });
    if let Some(errno) = refused {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // Report the filesystem's ACTUAL error. Collapsing everything to ENOENT
    // reads as "the source path is not there", which is a lie whenever the
    // source exists and the filesystem simply declined the operation — and
    // callers act on that difference. systemd's `rename_noreplace()` retries
    // via a link/unlink dance only on EINVAL/ENOSYS/ENOTTY and returns
    // anything else to its caller verbatim, while code all over systemd
    // treats ENOENT as "the source vanished, nothing to do". So an
    // unimplemented `DirOps::rename` surfacing as ENOENT turns a recoverable
    // "unsupported" into a permanent, silent give-up.
    match outcome {
        Some(Some(Ok(()))) => ctx.set_return(SyscallReturn::ok(0)),
        Some(Some(Err(e))) => {
            let errno = match e {
                narf_filesystem::FsError::NotFound => ENOENT,
                narf_filesystem::FsError::PermissionDenied => EACCES,
                narf_filesystem::FsError::InvalidPath => EINVAL,
                narf_filesystem::FsError::CrossDevice => EXDEV,
                narf_filesystem::FsError::Busy => EBUSY,
                narf_filesystem::FsError::ReadOnly => EROFS,
                narf_filesystem::FsError::NoSpace => ENOSPC,
                narf_filesystem::FsError::InvalidData => EINVAL,
                // EINVAL, deliberately, not EOPNOTSUPP: it is the errno
                // systemd's rename_noreplace() treats as "try the fallback",
                // and Linux itself returns EINVAL for a rename a filesystem
                // cannot perform.
                narf_filesystem::FsError::Unsupported => EINVAL,
                _ => EINVAL,
            };
            ctx.set_return(errno_ret(errno));
        }
        // The parent directory itself did not resolve — the one case where
        // ENOENT is the honest answer.
        _ => ctx.set_return(errno_ret(ENOENT)),
    }
}
