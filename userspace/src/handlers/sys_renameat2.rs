#[allow(unused_imports)]
use super::*;

/// `renameat2(olddirfd, old, newdirfd, new, flags)` — rename with
/// RENAME_NOREPLACE (fail if the destination exists) or RENAME_EXCHANGE
/// (atomically swap two names; needs a backend `DirOps::rename_to` that
/// implements it, EINVAL otherwise). RENAME_WHITEOUT isn't supported (EINVAL).
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
    const RENAME_EXCHANGE: u32 = 2;
    const RENAME_WHITEOUT: u32 = 4;
    // `do_renameat2` validates the flags before it walks either name, so a
    // bad flag or combination outranks -EFAULT, an empty path and a bad
    // dirfd:
    //
    //     if (flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT))
    //             return -EINVAL;
    //     if ((flags & (RENAME_NOREPLACE | RENAME_WHITEOUT)) &&
    //         (flags & RENAME_EXCHANGE))
    //             return -EINVAL;
    //
    // A bare -1 lands in glibc's [-4095,-1] errno window as EPERM, which
    // reads as a permission problem; return real errnos instead.
    if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0
        || ((flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0) && (flags & RENAME_EXCHANGE != 0))
    {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    if flags & RENAME_WHITEOUT != 0 {
        // No NARF filesystem can create a whiteout; Linux answers a flag the
        // backend does not implement with EINVAL.
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let old_path = match copy_user_cstr_checked(old_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    // The old name is walked before the new name's `getname()` error is
    // examined: an empty old name (-ENOENT) outranks an unreadable new one.
    if old_path.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    let new_path = match copy_user_cstr_checked(new_uptr, 4096) {
        Ok(s) => s,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    if new_path.is_empty() {
        ctx.set_return(errno_ret(ENOENT));
        return;
    }
    // glibc implements plain `rename(2)` on top of renameat2, so this is
    // the path a distro's libc actually takes — it has to resolve
    // relative paths against the cwd exactly like `sys_rename` does.
    let task = current_task_id();
    let old_last = LastComponent::of(&old_path);
    let new_last = LastComponent::of(&new_path);
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
    // One body for rename/renameat/renameat2: the errno ORDER of
    // `do_renameat2` lives in `rename_impl`. This handler used to carry its
    // own copy with its own FsError table (a non-empty destination came back
    // EBUSY here and EEXIST from rename(2)), and decided RENAME_NOREPLACE's
    // EEXIST before checking that the source existed.
    rename_absolute(ctx, &old_path, &new_path, old_last, new_last, flags);
}
