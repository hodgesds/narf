#[allow(unused_imports)]
use super::*;

/// `include/uapi/linux/stat.h`: `STATX__RESERVED 0x80000000U` — held back for
/// a future `struct statx` field. `do_statx` rejects it so that a binary
/// built against a newer header cannot silently get a short answer.
const STATX_RESERVED: u32 = 0x8000_0000;

/// `fs/stat.c::SYSCALL_DEFINE5(statx)` and the two helpers it dispatches to
/// fix both the errnos and the order they are decided in:
///
/// ```text
///     CLASS(filename_maybe_null, name)(filename, flags);
///     if (!name && dfd >= 0)
///             return do_statx_fd(dfd, flags & ~AT_NO_AUTOMOUNT, mask, buffer);
///     return do_statx(dfd, name, flags, mask, buffer);
///
/// int do_statx(...)                             /* and do_statx_fd, identically */
/// {
///         if (mask & STATX__RESERVED)                        return -EINVAL;
///         if ((flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE) return -EINVAL;
///         error = vfs_statx(dfd, filename, flags, &stat, mask);
///         if (error) return error;
///         return cp_statx(&stat, buffer);        /* copy_to_user → -EFAULT */
/// }
///
/// static int vfs_statx(...)
/// {
///         if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH |
///                       AT_STATX_SYNC_TYPE))                 return -EINVAL;
///         error = filename_lookup(dfd, filename, lookup_flags, &path, NULL);
///         ...
/// }
/// ```
///
/// So: the mask and sync-type checks come first — a reserved mask bit beats
/// ENOENT on a missing path, and beats EFAULT on the pathname pointer too,
/// because `getname()`'s error is only surfaced later by `filename_lookup`.
/// The destination buffer is inspected last, in `cp_statx`. And the
/// descriptor branch (`do_statx_fd` → `vfs_statx_fd`) never reaches
/// `vfs_statx`, so it does NOT validate `flags` at all — only the fd's
/// existence, as -EBADF.
///
/// Getting the numbers right matters most on the lookup arm: musl and glibc
/// implement `stat()`/`lstat()`/`fstatat()` on top of `statx` where it is
/// available, so a bare -1 here surfaces as errno 1 = EPERM for every
/// "does this file exist?" probe in userspace — PATH search over a
/// `:`-separated list, a config-file cascade (`/etc/x` then `~/.x`), and
/// every "create it if it is not there" path. Those all key on ENOENT and
/// treat EPERM as a hard, reportable error.
pub(crate) fn sys_statx(ctx: &mut dyn TrapContext) {
    use linux_compat::*;
    let args = *ctx.args();
    // Linux ABI: `int statx(int dirfd, const char *path, int flags,
    // unsigned int mask, struct statx *buf)`. arg2/3/4/5 shift left
    // by one slot now that arg2 is `flags` (not the old NARF-native
    // `path_len`). Widths match the kernel prototype: `int dfd`,
    // `unsigned flags`, `unsigned int mask`.
    let dirfd = args.arg0 as i32;
    let path_uptr = args.arg1;
    let flags = args.arg2 as u32;
    let mask = args.arg3 as u32;
    let out_ptr = args.arg4 as *mut Statx;

    // do_statx / do_statx_fd, before anything is resolved.
    if mask & STATX_RESERVED != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    // AT_STATX_SYNC_TYPE is a 2-bit field; asking for FORCE_SYNC and
    // DONT_SYNC at once is contradictory, and only that combination is
    // rejected (each bit on its own is a legal sync mode).
    if flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    // AT_EMPTY_PATH + empty path string → operate on dirfd directly.
    // We can detect "empty path" cheaply by reading just the first
    // byte; if it's NUL, no need to call copy_user_cstr. `getname_maybe_null`
    // also maps a NULL `filename` under AT_EMPTY_PATH to "empty".
    let empty = (flags & AT_EMPTY_PATH) != 0
        && (path_uptr == 0 || {
            let mut first = [0u8; 1];
            // SAFETY: `path_uptr` is the user path pointer; copy_from_user
            // range-validates it and SMAP-brackets the 1-byte read into `first`.
            // SAFETY: Valid memory or trusted environment
            unsafe { copy_from_user(&mut first, path_uptr) }.is_ok() && first[0] == 0
        });

    // Resolve to a FileOps. Three cases:
    //   1. empty + dirfd >= 0       → do_statx_fd: look up the fd, -EBADF if
    //                                  the table does not hold it. No flag
    //                                  validation on this branch.
    //   2. empty + dirfd == AT_FDCWD → LOOKUP_EMPTY resolves "" against the
    //                                  cwd; any other negative dirfd is
    //                                  -EBADF from path_init's fdget.
    //   3. otherwise                → vfs_statx: validate `flags`, then walk.
    let (fs_stat, mnt_id, is_mount_root) = if empty && dirfd >= 0 {
        let task = current_task_id();
        let st = fd::with_table(task, |t| {
            t.get(dirfd as u32).map(|e| {
                let (uid, gid) = e.ops.owners();
                (e.ops.stat(), e.ops.ino(), e.ops.rdev(), uid, gid)
            })
        })
        .flatten();
        let Some(st) = st else {
            // vfs_statx_fd's `fd_empty(f)` arm. A closed descriptor is EBADF,
            // never ENOENT: the caller asked about an fd, not a name.
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        };
        // The mount id of the mount this fd resides on. systemd's
        // path_is_root_at / fds_inode_and_mount_same compare STATX_MNT_ID to
        // distinguish a bind/pivoted root from the real root; absent it,
        // statx_mount_same returns -ENODATA and a service's mount-namespace
        // setup fails with 226/EXIT_NAMESPACE (systemd-udevd et al.).
        // An O_PATH fd does not currently retain a mount-root marker.  Its
        // mount identity remains available, while pathname statx below
        // carries STATX_ATTR_MOUNT_ROOT for systemd's mount-point probe.
        (
            Some(st),
            crate::mqueue::fd_mount_id(task, dirfd as u32),
            false,
        )
    } else {
        // vfs_statx's flag gate. It precedes filename_lookup, so an unknown
        // flag bit outranks a missing path.
        const ALLOWED_FLAGS: u32 =
            AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE;
        if flags & !ALLOWED_FLAGS != 0 {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
        const AT_FDCWD_I32: i32 = AT_FDCWD;
        let raw = if empty {
            // Reached only for a negative dirfd (the >= 0 case is above).
            if dirfd != AT_FDCWD_I32 {
                ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
                return;
            }
            // LOOKUP_EMPTY against AT_FDCWD == the cwd itself.
            alloc::string::String::from(".")
        } else {
            match copy_user_cstr(path_uptr, 4096) {
                Some(s) => s,
                None => {
                    // LINUX-GAP: `getname()` reports -ENAMETOOLONG for a
                    // pathname >= PATH_MAX with no NUL and -EFAULT for an
                    // unreadable one; copy_user_cstr collapses both to `None`.
                    ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
                    return;
                }
            }
        };
        if raw.is_empty() {
            // A non-AT_EMPTY_PATH empty name never resolves.
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
            return;
        }
        // Honour a real directory fd (same shape as sys_readlinkat):
        // resolve a relative path against the directory backing `dirfd`.
        // systemd's chase() walks a path one component at a time via
        // statx(parent_dir_fd, name, AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH,
        // STATX_TYPE); without this branch every such lookup resolved
        // against the CWD instead and ENOENT'd (exec_setup_credentials'
        // mount-ns child → journald 243/EXIT_CREDENTIALS).
        let relative = !raw.starts_with('/');
        if relative && dirfd < 0 && dirfd != AT_FDCWD_I32 {
            // path_init's `fdget(nd->dfd)` on a bogus anchor.
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
        let effective = if !relative || dirfd == AT_FDCWD_I32 {
            raw
        } else {
            match fd_path_for_task(current_task_id(), dirfd as u32) {
                Some(dir) if dir.starts_with('/') => {
                    alloc::format!("{}/{}", dir.trim_end_matches('/'), raw)
                }
                _ => raw,
            }
        };
        // resolve_cwd_path resolves against the cwd AND re-roots under
        // the task's chroot — applying apply_chroot again double-composes.
        let path_owned = resolve_cwd_path(current_task_id(), &effective);
        // AT_SYMLINK_NOFOLLOW → describe the symlink itself (S_IFLNK),
        // not its target; otherwise follow like plain stat.
        let follow_final = flags & AT_SYMLINK_NOFOLLOW == 0;
        let st = stat_ino_path_dir_aware_ext(&path_owned, follow_final);
        let is_mount_root = current_path_is_mount_root(&path_owned);
        (st, current_mount_id_at(&path_owned), is_mount_root)
    };

    let (s, ino, rdev, uid, gid) = match fs_stat {
        Some(tuple) => tuple,
        None => {
            // File doesn't exist — report ENOENT, not the bare -1 sentinel
            // (which musl maps to EPERM). Callers that probe for a path's
            // existence (e.g. libwayland's wl_socket_lock, which only
            // proceeds when stat() of the socket path returns ENOENT) need
            // the real errno.
            // LINUX-GAP: filename_lookup also yields -ENOTDIR, -ELOOP and
            // -EACCES here; the dir-aware resolver returns a bare `None`
            // with no failure reason, so they collapse into -ENOENT.
            ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // -ENOENT
            return;
        }
    };
    // dev_t (small encoding (major<<8)|minor) → statx major/minor fields.
    let (rdev_major, rdev_minor) = (((rdev >> 8) & 0xfff) as u32, (rdev & 0xff) as u32);

    let ftype_bits: u16 = match s.mode.file_type {
        narf_filesystem::FileType::File => 0o100000,
        narf_filesystem::FileType::Dir => 0o040000,
        narf_filesystem::FileType::Symlink => 0o120000,
        narf_filesystem::FileType::Special => 0o020000,
        narf_filesystem::FileType::Block => 0o060000,
        narf_filesystem::FileType::Socket => 0o140000,
        narf_filesystem::FileType::Fifo => 0o010000,
    };
    let mode_word: u16 = ftype_bits | (s.mode.perms & 0o7777);

    // mtime: monotonic cycles → ns via the wall-clock calibration.
    // Wall-clock per inode isn't tracked, so this surfaces a
    // stable monotonic ordering, not a real wall time.
    let mtime_ns = narf_time::cycles_to_ns(s.mtime_cycles);
    let mtime = StatxTimestamp {
        tv_sec: (mtime_ns / 1_000_000_000) as i64,
        tv_nsec: (mtime_ns % 1_000_000_000) as u32,
        __reserved: 0,
    };

    // Honour the request mask but only advertise what we filled.
    // STATX_BASIC_STATS = type|mode|nlink|uid|gid|atime|mtime|
    // ctime|ino|size|blocks. We fill type/mode/nlink/ino/size/
    // blocks/mtime/ctime; uid/gid/atime aren't tracked.
    //
    // LINUX-GAP: past the STATX__RESERVED rejection above, `mask` is
    // advisory here — the handler computes the same fields whatever is
    // requested and reports them all in stx_mask. Linux permits returning
    // MORE than was asked for (and systemd relies on that for STATX_MNT_ID,
    // below), but it also clears result_mask bits it could not fill, whereas
    // NARF has no source for STATX_BTIME / STATX_ATIME / STATX_DIOALIGN and
    // simply never advertises them. A caller asking only for STATX_BTIME
    // therefore gets a successful statx with that bit clear rather than an
    // error — which is legal, just less informative than Linux.
    let filled = STATX_TYPE
        | STATX_MODE
        | STATX_NLINK
        | STATX_UID
        | STATX_GID
        | STATX_INO
        | STATX_SIZE
        | STATX_BLOCKS
        | STATX_MTIME
        | STATX_CTIME
        | STATX_MNT_ID;
    // A mount ID is cheap once path resolution has identified the covering
    // mount, and Linux is permitted to return fields beyond the request.
    // systemd intentionally asks only for STATX_TYPE|STATX_INO while deciding
    // whether API filesystems are already mounted, then requires MNT_ID in
    // the reply to make that decision. Advertising it only when explicitly
    // requested made every such probe fail with EUNATCH despite statx(2)
    // itself succeeding.
    let mnt_id_mask = if mnt_id.is_some() { STATX_MNT_ID } else { 0 };
    // Linux advertises STATX_ATTR_MOUNT_ROOT support even when the queried
    // object is not a mount root, and sets the value bit only for the root of
    // the visible mount. systemd 258 uses this attribute (rather than an
    // extra mountinfo scan) for its early API-filesystem mount probe.
    let out = Statx {
        stx_blksize: 4096,
        stx_attributes: if is_mount_root {
            STATX_ATTR_MOUNT_ROOT
        } else {
            0
        },
        stx_mode: mode_word,
        stx_size: s.size,
        stx_blocks: s.blocks,
        stx_mtime: mtime,
        stx_ctime: mtime,
        stx_ino: if ino != 0 {
            ino
        } else {
            (s.mtime_cycles ^ (s.size << 1)) & 0x0fff_ffff_ffff_ffff
        },
        stx_nlink: 1,
        stx_uid: uid,
        stx_gid: gid,
        stx_rdev_major: rdev_major,
        stx_rdev_minor: rdev_minor,
        stx_mnt_id: mnt_id.unwrap_or(0),
        stx_attributes_mask: STATX_ATTR_MOUNT_ROOT,
        stx_mask: (filled
            & if mask == 0 {
                filled
            } else {
                mask | STATX_BASIC_STATS & filled
            })
            | mnt_id_mask,
        ..Default::default()
    };

    // cp_statx's arm: the destination is inspected only now, after the mask,
    // the flags and the lookup have all been accepted.
    if out_ptr.is_null() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    // SAFETY: Statx is repr(C) POD; bytes are valid for read.
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &out as *const Statx as *const u8,
            core::mem::size_of::<Statx>(),
        )
    };
    // SAFETY: `out_ptr` is the user statx buffer (null-checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `bytes`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr as u64, bytes) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
