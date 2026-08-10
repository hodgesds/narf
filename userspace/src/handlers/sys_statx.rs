#[allow(unused_imports)]
use super::*;

#[cfg(feature = "linux-compat")]
pub(crate) fn sys_statx(ctx: &mut dyn TrapContext) {
    use linux_compat::*;
    let args = *ctx.args();
    // Linux ABI: `int statx(int dirfd, const char *path, int flags,
    // unsigned int mask, struct statx *buf)`. arg2/3/4/5 shift left
    // by one slot now that arg2 is `flags` (not the old NARF-native
    // `path_len`).
    let dirfd = args.arg0 as i32;
    let path_uptr = args.arg1;
    let flags = args.arg2 as u32;
    let mask = args.arg3 as u32;
    let out_ptr = args.arg4 as *mut Statx;
    let _ = mask;

    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }

    // AT_EMPTY_PATH + empty path string → operate on dirfd directly.
    // We can detect "empty path" cheaply by reading just the first
    // byte; if it's NUL, no need to call copy_user_cstr.
    let mut first = [0u8; 1];
    // SAFETY: `path_uptr` is the user path pointer; copy_from_user range-validates
    // it and SMAP-brackets the 1-byte read into `first`.
    let empty = (flags & AT_EMPTY_PATH) != 0
        // SAFETY: Valid memory or trusted environment
        && unsafe { copy_from_user(&mut first, path_uptr) }.is_ok()
        && first[0] == 0;

    // Resolve to a FileOps. Three cases:
    //   1. empty + dirfd >= 0       → look up fd
    //   2. path absolute            → registry walk (dirfd ignored
    //                                  beyond requiring AT_FDCWD or
    //                                  a real fd; NARF has no per-
    //                                  task cwd so non-AT_FDCWD
    //                                  relative paths fail)
    //   3. otherwise                → fail
    let (fs_stat, mnt_id) = if empty {
        if dirfd < 0 {
            ctx.set_return(fail);
            return;
        }
        let task = current_task_id();
        let st = fd::with_table(task, |t| {
            t.get(dirfd as u32).map(|e| {
                let (uid, gid) = e.ops.owners();
                (e.ops.stat(), e.ops.ino(), e.ops.rdev(), uid, gid)
            })
        })
        .flatten();
        // The mount id of the mount this fd resides on. systemd's
        // path_is_root_at / fds_inode_and_mount_same compare STATX_MNT_ID to
        // distinguish a bind/pivoted root from the real root; absent it,
        // statx_mount_same returns -ENODATA and a service's mount-namespace
        // setup fails with 226/EXIT_NAMESPACE (systemd-udevd et al.).
        (st, crate::mqueue::fd_mount_id(task, dirfd as u32))
    } else {
        let raw = match copy_user_cstr(path_uptr, 4096) {
            Some(s) => s,
            None => {
                ctx.set_return(fail);
                return;
            }
        };
        // Honour a real directory fd (same shape as sys_readlinkat):
        // resolve a relative path against the directory backing `dirfd`.
        // systemd's chase() walks a path one component at a time via
        // statx(parent_dir_fd, name, AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH,
        // STATX_TYPE); without this branch every such lookup resolved
        // against the CWD instead and ENOENT'd (exec_setup_credentials'
        // mount-ns child → journald 243/EXIT_CREDENTIALS).
        const AT_FDCWD_I32: i32 = -100;
        let effective = if raw.starts_with('/') || dirfd == AT_FDCWD_I32 || dirfd < 0 {
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
        (st, current_mount_id_at(&path_owned))
    };

    let (s, ino, rdev, uid, gid) = match fs_stat {
        Some(tuple) => tuple,
        None => {
            // File doesn't exist — report ENOENT, not the bare -1 sentinel
            // (which musl maps to EPERM). Callers that probe for a path's
            // existence (e.g. libwayland's wl_socket_lock, which only
            // proceeds when stat() of the socket path returns ENOENT) need
            // the real errno.
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
    let out = Statx {
        stx_blksize: 4096,
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
        stx_mask: filled
            & if mask == 0 {
                filled
            } else {
                mask | STATX_BASIC_STATS & filled
            },
        ..Default::default()
    };

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
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
