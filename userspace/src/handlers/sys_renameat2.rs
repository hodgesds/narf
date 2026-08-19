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
    const RENAME_NOREPLACE: u32 = 1;
    // A bare -1 lands in glibc's [-4095,-1] errno window as EPERM, which
    // reads as a permission problem; return real errnos instead.
    let efault = SyscallReturn::ok((-14i64) as u64);
    let einval = SyscallReturn::ok((-22i64) as u64);
    if flags & !RENAME_NOREPLACE != 0 {
        ctx.set_return(einval);
        return;
    }
    let old_path = match copy_user_cstr(old_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(efault);
            return;
        }
    };
    let new_path = match copy_user_cstr(new_uptr, 4096) {
        Some(s) => s,
        None => {
            ctx.set_return(efault);
            return;
        }
    };
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
        let exists = current_resolve_parent_absolute(&new_path, |_fs, parent, leaf| parent.lookup(leaf).is_some())
            .unwrap_or(false);
        if exists {
            ctx.set_return(SyscallReturn::ok((-17i64) as u64)); // EEXIST
            return;
        }
    }
    // Different parent directories: a move within one mount, not
    // automatically EXDEV. See `cross_dir_rename`.
    if old_path[..old_split] != new_path[..new_split] {
        ctx.set_return(SyscallReturn::ok(cross_dir_rename(&old_path, &new_path)));
        return;
    }
    let outcome = current_resolve_parent_absolute(&old_path, |_fs, parent, old_leaf| {
            poll_blocking(parent.rename(old_leaf, new_leaf))
        });
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
            let errno: i64 = match e {
                narf_filesystem::FsError::NotFound => -2,          // ENOENT
                narf_filesystem::FsError::PermissionDenied => -13, // EACCES
                narf_filesystem::FsError::InvalidPath => -22,      // EINVAL
                narf_filesystem::FsError::CrossDevice => -18,      // EXDEV
                narf_filesystem::FsError::Busy => -16,             // EBUSY
                narf_filesystem::FsError::ReadOnly => -30,         // EROFS
                narf_filesystem::FsError::NoSpace => -28,          // ENOSPC
                narf_filesystem::FsError::InvalidData => -22,      // EINVAL
                // EINVAL, deliberately, not EOPNOTSUPP: it is the errno
                // systemd's rename_noreplace() treats as "try the fallback",
                // and Linux itself returns EINVAL for a rename a filesystem
                // cannot perform.
                narf_filesystem::FsError::Unsupported => -22,
                _ => -22, // EINVAL
            };
            ctx.set_return(SyscallReturn::ok(errno as u64));
        }
        // The parent directory itself did not resolve — the one case where
        // ENOENT is the honest answer.
        _ => ctx.set_return(SyscallReturn::ok((-2i64) as u64)),
    }
}
