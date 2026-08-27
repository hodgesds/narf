#[allow(unused_imports)]
use super::*;

/// `fs/stat.c::SYSCALL_DEFINE4(newfstatat)`:
///
/// ```text
///     error = vfs_fstatat(dfd, filename, &stat, flag);
///     if (unlikely(error)) return error;
///     return cp_new_stat(&stat, statbuf);
///
/// int vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat, int flags)
/// {
///         CLASS(filename_maybe_null, name)(filename, flags);
///         if (!name && dfd >= 0)
///                 return vfs_fstat(dfd, stat);            /* no flag check! */
///         return vfs_statx(dfd, name, flags | AT_NO_AUTOMOUNT, stat, STATX_BASIC_STATS);
/// }
/// ```
///
/// Two ordering details this file follows literally:
///
///   * The `AT_EMPTY_PATH`-with-a-live-fd branch is taken BEFORE any flag
///     validation — `vfs_fstat` never looks at `flags` — so a garbage flag
///     bit combined with `AT_EMPTY_PATH` and a real descriptor still
///     succeeds. glibc's `fstat` is exactly `newfstatat(fd, "", buf,
///     AT_EMPTY_PATH)`, and rejecting it for a stray high bit turns every
///     `fstat` into EINVAL.
///   * `vfs_statx`'s accepted flag set includes `AT_STATX_SYNC_TYPE`
///     (0x6000), not just the three `AT_*` bits fstatat(2) documents,
///     because fstatat funnels through the statx path. Rejecting those bits
///     breaks callers that pass a statx-shaped flag word through a
///     newfstatat wrapper.
///
/// The path lookup also runs before `cp_new_stat`, so the dirfd's
/// -EBADF/-ENOTDIR and the walk's -ENOENT all outrank a bad `statbuf`.
pub(crate) fn sys_newfstatat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux ABI: `int fstatat(int dirfd, const char *pathname,
    // struct stat *statbuf, int flags)`.
    let dirfd = args.arg0 as i32;
    let path_uptr = args.arg1;
    let stat_out = args.arg2;
    let flags = args.arg3 as u32;

    // AT_EMPTY_PATH + empty path → describe `dirfd` itself. This is how modern
    // glibc implements `fstat(fd, buf)`: `newfstatat(fd, "", buf,
    // AT_EMPTY_PATH)`. Without this, the empty path falls through to path
    // resolution and yields a garbage/ENOENT stat, so `fstat` on any open fd
    // reports a non-regular mode — which makes systemd's `read_full_virtual_file`
    // reject every sysfs `uevent` with EBADF and libudev resolve no devices
    // (kwin then gets no GPU). sys_statx already handles this; mirror it.
    //
    // `getname_maybe_null` also treats a NULL `filename` under AT_EMPTY_PATH
    // as "empty", so `newfstatat(fd, NULL, buf, AT_EMPTY_PATH)` is legal.
    let empty = (flags & linux_compat::AT_EMPTY_PATH) != 0
        && (path_uptr == 0 || {
            let mut first = [0u8; 1];
            // SAFETY: `path_uptr` is the user path pointer; copy_from_user
            // range-validates it and SMAP-brackets the 1-byte read into `first`.
            unsafe { copy_from_user(&mut first, path_uptr) }.is_ok() && first[0] == 0
        });
    if empty && dirfd >= 0 {
        // vfs_fstat: -EBADF for a descriptor the table does not hold, and no
        // flag validation on this branch at all.
        let out_ptr = stat_out as *mut linux_compat::Stat;
        let task = current_task_id();
        let stat = fd::with_table(task, |t| {
            t.get(dirfd as u32)
                .map(|e| (e.ops.stat(), e.ops.owners(), e.ops.rdev(), e.ops.ino()))
        });
        let (s, (uid, gid), rdev, ino) = match stat {
            Some(Some(tuple)) => tuple,
            _ => {
                ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
                return;
            }
        };
        // cp_new_stat's arm — only now is the destination inspected.
        if out_ptr.is_null() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
        let out = linux_stat_from_fs(s, uid, gid, rdev, ino);
        // SAFETY: `out` is a live repr(C) Stat; the slice spans exactly its size.
        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &out as *const linux_compat::Stat as *const u8,
                core::mem::size_of::<linux_compat::Stat>(),
            )
        };
        // SAFETY: `out_ptr` null-checked above; copy_to_user range-validates it.
        if unsafe { copy_to_user(out_ptr as u64, bytes) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // vfs_statx's flag gate, reached only on the path-lookup branch. It runs
    // before the walk, so an unknown flag bit beats -ENOENT on a missing
    // path.
    const ALLOWED_FLAGS: u32 = linux_compat::AT_EMPTY_PATH
        | linux_compat::AT_SYMLINK_NOFOLLOW
        | linux_compat::AT_NO_AUTOMOUNT
        | linux_compat::AT_STATX_SYNC_TYPE;
    if flags & !ALLOWED_FLAGS != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    // AT_SYMLINK_NOFOLLOW (lstat's shape via fstatat) means "describe the
    // symlink itself" — don't follow the final component. Without it,
    // fstatat follows like plain stat.
    let follow_final = flags & linux_compat::AT_SYMLINK_NOFOLLOW == 0;

    if empty {
        // dirfd >= 0 was handled above. What is left is AT_EMPTY_PATH with a
        // negative dirfd: LOOKUP_EMPTY makes `filename_lookup` resolve the
        // empty name against the anchor, so AT_FDCWD stats the cwd and any
        // other negative value is `path_init`'s fdget failure.
        if dirfd == linux_compat::AT_FDCWD {
            stat_linux_path(ctx, ".", stat_out, follow_final);
        } else {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        }
        return;
    }

    // `getname()`: -EFAULT for an unreadable pointer, -ENAMETOOLONG for a
    // path at PATH_MAX with no terminator.
    let raw = match copy_user_cstr_checked(path_uptr, 4096) {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    if raw.is_empty() {
        // Without AT_EMPTY_PATH there is no LOOKUP_EMPTY, so "" never
        // resolves.
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
        return;
    }
    // Linux resolves a relative pathname beneath dirfd. Journald creates its
    // runtime journal and subsequently validates directory entries through
    // `newfstatat(parent_fd, "system.journal", AT_SYMLINK_NOFOLLOW)`; treating
    // that name as cwd-relative made it lose the file it had just created.
    let effective = match resolve_at_path(current_task_id(), dirfd as i64, &raw) {
        Ok(path) => path,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    // LINUX-GAP: `stat_linux_path` (core.inc.rs) checks its destination
    // pointer BEFORE resolving, so `newfstatat(AT_FDCWD, "/missing", NULL, 0)`
    // still reports -EFAULT where Linux reports -ENOENT. Fixing that means
    // reordering the shared helper, which is outside this file.
    stat_linux_path(ctx, &effective, stat_out, follow_final);
}
