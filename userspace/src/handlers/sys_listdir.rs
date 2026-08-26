#[allow(unused_imports)]
use super::*;

const ENOENT: i64 = 2;
const EFAULT: i64 = 14;
const ENOTDIR: i64 = 20;
const EINVAL: i64 = 22;
const ENAMETOOLONG: i64 = 36;

#[inline]
fn fail(errno: i64) -> SyscallReturn {
    SyscallReturn::ok((-errno) as u64)
}

/// `listdir` is NARF-native — there is no Linux syscall of this name — but it
/// is `getdents64(2)` with the directory named by path instead of by an open
/// fd, so it borrows that call's errno shape and check ORDER from
/// `fs/readdir.c`:
///
/// ```text
///   iterate_dir():  int res = -ENOTDIR;
///                   if (!file->f_op->iterate_shared) goto out;
///   filldir64():    buf->error = -EINVAL;   /* only used if we fail.. */
///                   if (reclen > ctx->count) return false;
///                   if (!user_write_access_begin(...)) goto efault;
/// ```
///
/// plus `user_path_at`'s `-ENOENT` for a name that resolves to nothing, since
/// this call does its own lookup rather than inheriting an already-open fd.
///
/// Every one of those was the bare `-1` sentinel, which libc decodes as
/// EPERM. A directory walker cannot act on that: "the directory is gone"
/// (retry the parent), "that is a file, not a directory" (stop descending)
/// and "your buffer is too small for this name" (grow the buffer and repeat
/// the same cursor) all demand different recovery, and all three arrived as
/// "Operation not permitted".
///
/// The ORDER matters as much as the values. Linux resolves the directory
/// before it looks at the output buffer, and `filldir64` is only reached once
/// there is an entry to emit — so an exhausted cursor returns 0 without ever
/// inspecting the buffer, and a too-small buffer is EINVAL (not EFAULT) even
/// when the pointer is also unusable.
pub(crate) fn sys_listdir(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let path_ptr = args.arg0;
    let path_len = args.arg1 as usize;
    let cursor = args.arg2 as usize;
    let out_ptr = args.arg3 as *mut u8;
    let out_len = args.arg4 as usize;

    // Path first, buffer second — `iterate_dir` runs before `filldir64`.
    // An empty pathname names nothing (Linux `user_path_at(AT_FDCWD, "")`
    // is -ENOENT), an over-long one is -ENAMETOOLONG, and only an actual
    // copy fault is -EFAULT. `copy_user_path` folds all three into `None`,
    // so the two argument cases are split out ahead of it.
    if path_len == 0 {
        ctx.set_return(fail(ENOENT));
        return;
    }
    if path_len > 4096 {
        ctx.set_return(fail(ENAMETOOLONG));
        return;
    }
    let path = match copy_user_path(path_ptr, path_len) {
        Some(s) => s,
        None => {
            ctx.set_return(fail(EFAULT));
            return;
        }
    };

    // Resolve to a DirOps. Empty path or root → use the FS root
    // directly; otherwise descend through `lookup_dir_async` so
    // disk-backed FSes (FAT, ext2) that only implement the async side
    // can serve subdirectory walks.
    let entries = narf_filesystem::registry()
        .resolve_absolute(&path, |fs, rel| {
            let dir: alloc::sync::Arc<dyn narf_filesystem::DirOps> = if rel.is_empty() {
                fs.root()
            } else {
                // Walk segment by segment via the async lookup so
                // disk-backed FSes (FAT, ext2) resolve correctly.
                let mut cur = fs.root();
                for seg in rel.split('/').filter(|s| !s.is_empty()) {
                    cur = poll_blocking(cur.lookup_dir_async(seg)).and_then(|r| r.ok())?;
                }
                cur
            };
            // Use enumerate_async so disk-backed FSes (FAT, ext2) that
            // return Vec::new() from the sync enumerate() still work.
            // poll_blocking drives the future to completion via the
            // same internally-polled NVMe/virtio-blk driver path that
            // sys_open and sys_read already rely on.
            poll_blocking(dir.enumerate_async(cursor, 1)).and_then(|r| r.ok())
        })
        .flatten();

    let entries = match entries {
        Some(v) => v,
        None => {
            // Linux splits this: the lookup itself fails with -ENOENT when
            // nothing of that name exists, while a name that DOES resolve
            // but has no `iterate_shared` is -ENOTDIR from `iterate_dir`.
            // A caller descending a tree branches on exactly this — ENOENT
            // means "raced with a rename, restart", ENOTDIR means "this is
            // a leaf, stop".
            let errno = if stat_path_dir_aware(&path).is_some() {
                ENOTDIR
            } else {
                ENOENT
            };
            ctx.set_return(fail(errno));
            return;
        }
    };
    if entries.is_empty() {
        // End of directory. `filldir64` is never invoked, so Linux reports
        // 0 without touching the output buffer at all — an exhausted cursor
        // succeeds even against a NULL or undersized one.
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let (name, ftype) = &entries[0];
    let name_bytes = name.as_bytes();
    let total = 8 + name_bytes.len();
    // `filldir64`: `reclen > ctx->count` is -EINVAL, and it is tested BEFORE
    // the user-access window opens. "Grow the buffer and re-issue the same
    // cursor" is a recoverable answer; EFAULT and EPERM are not.
    if total > out_len {
        ctx.set_return(fail(EINVAL));
        return;
    }
    if out_ptr.is_null() {
        ctx.set_return(fail(EFAULT));
        return;
    }
    // Encode FileType to the wire ordinal: 0=File, 1=Dir, 2=Symlink,
    // 3=Special, 4=Socket, 5=Fifo, 6=Block. New values append so the
    // existing NARF-native wire ordinals remain stable.
    let ftype_wire: u32 = match ftype {
        narf_filesystem::FileType::File => 0,
        narf_filesystem::FileType::Dir => 1,
        narf_filesystem::FileType::Symlink => 2,
        narf_filesystem::FileType::Special => 3,
        narf_filesystem::FileType::Socket => 4,
        narf_filesystem::FileType::Fifo => 5,
        narf_filesystem::FileType::Block => 6,
    };
    // Build the 8-byte header in kernel memory, then copy the whole
    // record (header + name) into user space under the SMAP bracket.
    let mut record = alloc::vec![0u8; total];
    record[..4].copy_from_slice(&(name_bytes.len() as u32).to_ne_bytes());
    record[4..8].copy_from_slice(&ftype_wire.to_ne_bytes());
    record[8..].copy_from_slice(name_bytes);
    // SAFETY: `out_ptr` is the user dirent buffer (null-checked, `total <= out_len`);
    // copy_to_user range-validates it and SMAP-brackets the write of `record`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr as u64, &record) }.is_err() {
        // `filldir64`'s `efault:` label — the record could not be handed to
        // the caller's buffer.
        ctx.set_return(fail(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(total as u64));
}
