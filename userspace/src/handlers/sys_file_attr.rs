#[allow(unused_imports)]
use super::*;

// `file_getattr(2)` / `file_setattr(2)` — the syscall form of the
// `FS_IOC_GETFLAGS` / `FS_IOC_SETFLAGS` ioctl pair, added because an ioctl
// needs an open descriptor and these take a path.

/// `FILE_ATTR_SIZE_VER0` — `sizeof(struct file_attr)`:
/// `{ __u64 fa_xflags; __u32 fa_extsize, fa_nextents, fa_projid, fa_cowextsize; }`.
const FILE_ATTR_SIZE_VER0: u64 = 24;

/// `FS_XFLAGS_MASK` (`include/linux/fileattr.h`) — every xflag this ABI
/// defines. Taken from the header rather than assembled by hand: it is the
/// union of five sub-masks, and `file_attr_to_fileattr` rejects anything
/// outside it with -EINVAL, so an over-wide value here would accept flags
/// Linux refuses.
const FS_XFLAGS_MASK: u64 = 0x8003_fffb;

/// `FS_XFLAG_RDONLY_MASK` — flags that are reported but never set
/// (`PREALLOC | HASATTR | VERITY`). `file_attr_to_fileattr` strips these
/// before handing the value on, so setting them is silently ignored rather
/// than refused.
const FS_XFLAG_RDONLY_MASK: u64 = 0x8002_0002;

const FS_XFLAG_IMMUTABLE: u64 = 0x0000_0008;
const FS_XFLAG_APPEND: u64 = 0x0000_0010;

/// Both syscalls open with this, BEFORE the `usize` checks:
///
/// ```text
/// if ((at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0) return -EINVAL;
/// if (!(at_flags & AT_SYMLINK_NOFOLLOW)) lookup_flags |= LOOKUP_FOLLOW;
/// if (usize > PAGE_SIZE) return -E2BIG;
/// ```
///
/// so a bad `at_flags` with an oversized `usize` is EINVAL, not E2BIG
/// (probed on Linux 6.18).
fn file_attr_at_flags_ok(at_flags: u32) -> Result<(), i64> {
    const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
    const AT_EMPTY_PATH: u32 = 0x1000;
    if at_flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(-EINVAL);
    }
    Ok(())
}

/// The `(dfd, filename, at_flags)` lookup these two share (the `at_flags`
/// check has already run).
///
/// ```text
/// CLASS(filename_maybe_null, name)(filename, at_flags);
/// if (!name && dfd >= 0) { CLASS(fd, f)(dfd); if (fd_empty(f)) return -EBADF;
///                          filepath = fd_file(f)->f_path; }
/// else                   { filename_lookup(dfd, name, lookup_flags, &filepath, NULL); }
/// ```
///
/// `CLASS(fd, ...)` is `fdget`, which does not hand out O_PATH files, and an
/// AT_FDCWD with an empty name reaches `filename_lookup`, whose empty walk is
/// the cwd (both probed on Linux 6.18). A directory is an inode with flags
/// too, but path resolution hands back `DirOps` for one, hence
/// [`XattrTarget`] rather than a bare `FileOps`.
///
/// Returns the target and, for the path form, the path (`mnt_want_write`
/// needs it).
fn file_attr_target(
    dfd: i64,
    path_ptr: u64,
    at_flags: u32,
) -> Result<(XattrTarget, Option<alloc::string::String>), i64> {
    const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
    const AT_EMPTY_PATH: u32 = 0x1000;
    const AT_FDCWD: i64 = -100;
    let follow = at_flags & AT_SYMLINK_NOFOLLOW == 0;
    let task = current_task_id();
    let dfd = dfd as i32 as i64;

    let raw = if path_ptr == 0 {
        if at_flags & AT_EMPTY_PATH == 0 {
            return Err(-EFAULT); // getname on a NULL pointer
        }
        alloc::string::String::new()
    } else {
        let raw = copy_user_cstr_checked(path_ptr, 4096).map_err(|e| -e)?;
        if raw.is_empty() && at_flags & AT_EMPTY_PATH == 0 {
            return Err(-ENOENT); // "" without AT_EMPTY_PATH
        }
        raw
    };
    let raw: &str = if raw.is_empty() {
        if dfd == AT_FDCWD {
            "."
        } else if dfd < 0 {
            return Err(-EBADF);
        } else {
            let ops = crate::fd::with_table(task, |t| {
                let entry = t.get(dfd as u32)?;
                if t.status_flags(dfd as u32).unwrap_or(0) & crate::fd::O_PATH != 0 {
                    return None;
                }
                Some(entry.ops.clone())
            })
            .flatten()
            .ok_or(-EBADF)?;
            return Ok((XattrTarget::File(ops), None));
        }
    } else {
        &raw
    };
    // `resolve_cwd_path`, not a bare `apply_chroot`: a RELATIVE name must be
    // joined onto the cwd before anything can resolve it.
    let anchored = resolve_cwd_path(task, &resolve_at_path(task, dfd, raw)?);
    // The VFS-level symlink walk, as `open` runs it — only this can follow
    // an ABSOLUTE target out of the filesystem the link lives on, which the
    // in-filesystem resolver cannot.
    let resolved = resolve_vfs_symlink_path(&anchored, follow).unwrap_or(anchored);
    let target = resolve_file_absolute_ext(&resolved, follow)
        .map(XattrTarget::File)
        .or_else(|| resolve_dir_absolute(&resolved).map(XattrTarget::Dir));
    match target {
        Some(target) => Ok((target, Some(resolved))),
        // `filename_lookup`'s own errno: ENOENT, ENOTDIR, ELOOP, EACCES.
        None => Err(-path_lookup_errno(&resolved)),
    }
}

/// `vfs_fileattr_get` / `_set` begin with `if (!inode->i_op->fileattr_get)
/// return -ENOIOCTLCMD;`, which these syscalls report as -EOPNOTSUPP. Only
/// regular files and directories carry the operation; a symlink (reached
/// with AT_SYMLINK_NOFOLLOW), a FIFO or a device node does not (probed on
/// Linux 6.18).
fn file_attr_supported(target: &XattrTarget) -> bool {
    match target {
        XattrTarget::File(file) => matches!(
            file.stat().mode.file_type,
            narf_filesystem::FileType::File | narf_filesystem::FileType::Dir
        ),
        XattrTarget::Dir(_) => true,
    }
}

/// The inode's `FS_*_FL` word. A `DirOps` directory models none.
fn file_attr_flags(target: &XattrTarget) -> u32 {
    match target {
        XattrTarget::File(file) => file.inode_flags(),
        XattrTarget::Dir(_) => 0,
    }
}

/// `usize` handling, shared by both. Note the ORDER — E2BIG before EINVAL,
/// so an oversized `usize` reports E2BIG even though it is also not a
/// version this kernel knows:
///
/// ```text
/// if (usize > PAGE_SIZE)             return -E2BIG;
/// if (usize < FILE_ATTR_SIZE_VER0)   return -EINVAL;
/// ```
fn file_attr_usize_ok(usize_bytes: u64) -> Result<(), i64> {
    if usize_bytes > 4096 {
        return Err(-E2BIG);
    }
    if usize_bytes < FILE_ATTR_SIZE_VER0 {
        return Err(-EINVAL);
    }
    Ok(())
}

/// `fs/file_attr.c::SYSCALL_DEFINE5(file_getattr)` — x86_64/arm64 468.
pub(crate) fn sys_file_getattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let (dfd, path_ptr, ufattr, usize_bytes, at_flags) =
        (a.arg0 as i64, a.arg1, a.arg2, a.arg3, a.arg4 as u32);

    if let Err(errno) =
        file_attr_at_flags_ok(at_flags).and_then(|()| file_attr_usize_ok(usize_bytes))
    {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    let target = match file_attr_target(dfd, path_ptr, at_flags) {
        Ok((target, _)) => target,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    if !file_attr_supported(&target) {
        ctx.set_return(errno_ret(EOPNOTSUPP));
        return;
    }
    // `fileattr_to_file_attr`: the inode's FS_*_FL word, reported as the
    // xfs-style xflags this ABI uses. NARF models the two the VFS enforces.
    let flags = file_attr_flags(&target);
    let mut xflags = 0u64;
    if u64::from(flags) & u64::from(narf_filesystem::FS_IMMUTABLE_FL) != 0 {
        xflags |= FS_XFLAG_IMMUTABLE;
    }
    if u64::from(flags) & u64::from(narf_filesystem::FS_APPEND_FL) != 0 {
        xflags |= FS_XFLAG_APPEND;
    }
    // fa_extsize / fa_nextents / fa_projid / fa_cowextsize stay 0: NARF has
    // no extent allocator and no project quotas, so there is no value to
    // report and 0 is what a filesystem without them reports.
    //
    // `copy_struct_to_user` writes min(usize, sizeof) and ZERO-FILLS the
    // rest of a larger caller struct (`clear_user`), so a newer caller never
    // reads stale bytes as fields this kernel does not know.
    let mut fattr = alloc::vec![0u8; usize_bytes as usize];
    fattr[0..8].copy_from_slice(&xflags.to_ne_bytes());
    // SAFETY: `ufattr` is the user `struct file_attr`; copy_to_user
    // range-validates it and brackets the write of `usize` bytes.
    if unsafe { copy_to_user(ufattr, &fattr) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

/// `fs/file_attr.c::SYSCALL_DEFINE5(file_setattr)` — x86_64/arm64 469.
///
/// The permission rules are `fileattr_set_prepare`'s and
/// `may_fileattr_set`'s, the same two the `FS_IOC_SETFLAGS` ioctl applies:
/// changing IMMUTABLE or APPEND needs CAP_LINUX_IMMUTABLE, and any change at
/// all needs ownership or CAP_FOWNER. Note the first is about the CHANGE and
/// not the value — a caller may rewrite the word as long as those two bits
/// keep the value they already had.
pub(crate) fn sys_file_setattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let (dfd, path_ptr, ufattr, usize_bytes, at_flags) =
        (a.arg0 as i64, a.arg1, a.arg2, a.arg3, a.arg4 as u32);

    if let Err(errno) =
        file_attr_at_flags_ok(at_flags).and_then(|()| file_attr_usize_ok(usize_bytes))
    {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    // `copy_struct_from_user`: the struct is read BEFORE the path is
    // resolved, so a bad `ufattr` is -EFAULT even when the path is also bad.
    let mut fattr = [0u8; FILE_ATTR_SIZE_VER0 as usize];
    let n = core::cmp::min(usize_bytes as usize, fattr.len());
    // SAFETY: `ufattr` is the user `struct file_attr`; copy_from_user
    // range-validates it and brackets the read of `n` bytes.
    if unsafe { copy_from_user(&mut fattr[..n], ufattr) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    // Every byte past the struct this kernel knows must be zero, or -E2BIG —
    // so a caller setting a field this kernel would ignore is told.
    if usize_bytes > FILE_ATTR_SIZE_VER0 {
        let rest = (usize_bytes - FILE_ATTR_SIZE_VER0) as usize;
        // SAFETY: the tail lies inside the caller-declared struct.
        let tail = match unsafe { copy_from_user_vec(ufattr + FILE_ATTR_SIZE_VER0, rest) } {
            Ok(v) => v,
            Err(_) => {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
        };
        if tail.iter().any(|&b| b != 0) {
            ctx.set_return(errno_ret(E2BIG));
            return;
        }
    }
    let xflags = u64::from_ne_bytes(fattr[0..8].try_into().unwrap());
    // `if (fattr->fa_xflags & ~mask) return -EINVAL;`
    if xflags & !FS_XFLAGS_MASK != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // `fileattr_fill_xflags(fa, fattr->fa_xflags & ~FS_XFLAG_RDONLY_MASK)` —
    // the read-only flags are STRIPPED rather than refused.
    let settable = xflags & !FS_XFLAG_RDONLY_MASK;
    let mut requested = 0u32;
    if settable & FS_XFLAG_IMMUTABLE != 0 {
        requested |= narf_filesystem::FS_IMMUTABLE_FL;
    }
    if settable & FS_XFLAG_APPEND != 0 {
        requested |= narf_filesystem::FS_APPEND_FL;
    }

    let (target, path) = match file_attr_target(dfd, path_ptr, at_flags) {
        Ok(found) => found,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    // `mnt_want_write(filepath.mnt)` before `vfs_fileattr_set`: a read-only
    // mount is EROFS (probed on Linux 6.18).
    if let Some(path) = path.as_deref() {
        if let Err(errno) = mnt_want_write(path) {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    }
    // `vfs_fileattr_set`: no `fileattr_set` op is -EOPNOTSUPP, ahead of the
    // ownership test.
    if !file_attr_supported(&target) {
        ctx.set_return(errno_ret(EOPNOTSUPP));
        return;
    }
    let task = current_task_id();
    // `may_fileattr_set`: "Verify that we are the owner or have CAP_FOWNER".
    let (uid, gid, ..) = target.meta();
    if !inode_owner_or_capable(task, uid, gid) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    let current = file_attr_flags(&target);
    // `fileattr_set_prepare`: it is the CHANGE to IMMUTABLE/APPEND that is
    // privileged, not the value.
    if (requested ^ current) & narf_filesystem::FS_PRIVILEGED_FL != 0
        && !capable(CAP_LINUX_IMMUTABLE)
    {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    let result = match &target {
        XattrTarget::File(ops) => match ops.set_inode_flags(requested) {
            Ok(()) => 0,
            // A filesystem that cannot store them must not pretend it did:
            // userspace would believe a file is immutable while nothing
            // enforces it. `file_getattr`/`file_setattr` map the ioctl's
            // ENOTTY to -EOPNOTSUPP, which is the answer this surface uses.
            Err(_) => -EOPNOTSUPP,
        },
        // A `DirOps` directory has no flag store: rewriting the (empty) word
        // unchanged is a no-op, anything else cannot be honoured.
        XattrTarget::Dir(_) if requested == current => 0,
        XattrTarget::Dir(_) => -EOPNOTSUPP,
    };
    ctx.set_return(SyscallReturn::ok(result as u64));
}
