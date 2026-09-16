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

/// The `(dfd, filename, at_flags)` prologue these two share.
///
/// ```text
/// if ((at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0) return -EINVAL;
/// if (!(at_flags & AT_SYMLINK_NOFOLLOW)) lookup_flags |= LOOKUP_FOLLOW;
/// CLASS(filename_maybe_null, name)(filename, at_flags);
/// if (!name && dfd >= 0) { CLASS(fd, f)(dfd); if (fd_empty(f)) return -EBADF;
///                          filepath = fd_file(f)->f_path; }
/// else                   { filename_lookup(dfd, name, lookup_flags, &filepath, NULL); }
/// ```
///
/// Unlike the xattr `*at` family, the AT_EMPTY_PATH arm needs the FILE
/// behind the descriptor rather than a side-table key, because inode flags
/// live on the inode itself.
fn file_attr_target(
    dfd: i64,
    path_ptr: u64,
    at_flags: u32,
) -> Result<alloc::sync::Arc<dyn narf_filesystem::FileOps>, i64> {
    const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
    const AT_EMPTY_PATH: u32 = 0x1000;
    const AT_FDCWD: i64 = -100;
    if at_flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(-22); // -EINVAL
    }
    let follow = at_flags & AT_SYMLINK_NOFOLLOW == 0;
    let task = current_task_id();

    let empty = if path_ptr == 0 {
        if at_flags & AT_EMPTY_PATH == 0 {
            return Err(-14); // -EFAULT: getname on a NULL pointer
        }
        true
    } else {
        let raw = copy_user_cstr_checked(path_ptr, 4096).map_err(|e| -e)?;
        if raw.is_empty() {
            if at_flags & AT_EMPTY_PATH == 0 {
                return Err(-2); // -ENOENT: "" without AT_EMPTY_PATH
            }
            true
        } else {
            let anchored = apply_chroot(&resolve_at_path(task, dfd, &raw)?);
            // The VFS-level symlink walk, as `open` runs it — only this can
            // follow an ABSOLUTE target out of the filesystem the link lives
            // on, which the in-filesystem resolver cannot.
            let resolved = resolve_vfs_symlink_path(&anchored, follow).unwrap_or(anchored);
            return resolve_file_absolute_ext(&resolved, false).ok_or(-2);
        }
    };
    debug_assert!(empty);
    // `if (!name && dfd >= 0)`: AT_FDCWD is not a descriptor, so it cannot
    // name a file and falls through to the path branch, which has no path.
    if dfd < 0 || dfd == AT_FDCWD {
        return Err(-9); // -EBADF
    }
    crate::fd::with_table(task, |t| t.get(dfd as u32).map(|e| e.ops.clone()))
        .flatten()
        .ok_or(-9)
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
        return Err(-7); // -E2BIG
    }
    if usize_bytes < FILE_ATTR_SIZE_VER0 {
        return Err(-22); // -EINVAL
    }
    Ok(())
}

/// `fs/file_attr.c::SYSCALL_DEFINE5(file_getattr)` — x86_64/arm64 468.
pub(crate) fn sys_file_getattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let (dfd, path_ptr, ufattr, usize_bytes, at_flags) =
        (a.arg0 as i64, a.arg1, a.arg2, a.arg3, a.arg4 as u32);

    if let Err(errno) = file_attr_usize_ok(usize_bytes) {
        ctx.set_return(SyscallReturn::ok(errno as u64));
        return;
    }
    let ops = match file_attr_target(dfd, path_ptr, at_flags) {
        Ok(ops) => ops,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    // `fileattr_to_file_attr`: the inode's FS_*_FL word, reported as the
    // xfs-style xflags this ABI uses. NARF models the two the VFS enforces.
    let flags = ops.inode_flags();
    let mut xflags = 0u64;
    if u64::from(flags) & u64::from(narf_filesystem::FS_IMMUTABLE_FL) != 0 {
        xflags |= FS_XFLAG_IMMUTABLE;
    }
    if u64::from(flags) & u64::from(narf_filesystem::FS_APPEND_FL) != 0 {
        xflags |= FS_XFLAG_APPEND;
    }
    let mut fattr = [0u8; FILE_ATTR_SIZE_VER0 as usize];
    fattr[0..8].copy_from_slice(&xflags.to_ne_bytes());
    // fa_extsize / fa_nextents / fa_projid / fa_cowextsize stay 0: NARF has
    // no extent allocator and no project quotas, so there is no value to
    // report and 0 is what a filesystem without them reports.
    //
    // `copy_struct_to_user` writes min(usize, sizeof) and zero-fills the
    // rest; a caller declaring a SMALLER struct than this kernel's gets the
    // prefix it asked for.
    let n = core::cmp::min(usize_bytes as usize, fattr.len());
    // SAFETY: `ufattr` is the user `struct file_attr`; copy_to_user
    // range-validates it and brackets the write of `n` bytes.
    if unsafe { copy_to_user(ufattr, &fattr[..n]) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
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

    if let Err(errno) = file_attr_usize_ok(usize_bytes) {
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
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
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
                ctx.set_return(SyscallReturn::ok((-14i64) as u64));
                return;
            }
        };
        if tail.iter().any(|&b| b != 0) {
            ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // -E2BIG
            return;
        }
    }
    let xflags = u64::from_ne_bytes(fattr[0..8].try_into().unwrap());
    // `if (fattr->fa_xflags & ~mask) return -EINVAL;`
    if xflags & !FS_XFLAGS_MASK != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
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

    let ops = match file_attr_target(dfd, path_ptr, at_flags) {
        Ok(ops) => ops,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok(errno as u64));
            return;
        }
    };
    let task = current_task_id();
    let current = ops.inode_flags();
    // `fileattr_set_prepare`: it is the CHANGE to IMMUTABLE/APPEND that is
    // privileged, not the value.
    if (requested ^ current) & narf_filesystem::FS_PRIVILEGED_FL != 0
        && !capable(CAP_LINUX_IMMUTABLE)
    {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
        return;
    }
    // `vfs_fileattr_set` -> `may_fileattr_set`: "Verify that we are the
    // owner or have CAP_FOWNER".
    let (uid, gid) = ops.owners();
    if !inode_owner_or_capable(task, uid, gid) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
        return;
    }
    let result = match ops.set_inode_flags(requested) {
        Ok(()) => 0,
        // A filesystem that cannot store them must not pretend it did:
        // userspace would believe a file is immutable while nothing
        // enforces it. `file_getattr`/`file_setattr` map the ioctl's
        // ENOTTY to -EOPNOTSUPP, which is the answer this surface uses.
        Err(_) => -95i64,
    };
    ctx.set_return(SyscallReturn::ok(result as u64));
}
