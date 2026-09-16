#[allow(unused_imports)]
use super::*;

/// `mm/filemap.c::SYSCALL_DEFINE4(cachestat)` — x86_64/arm64 451.
///
/// ```text
/// CLASS(fd, f)(fd);
/// if (fd_empty(f))                                 return -EBADF;
/// if (copy_from_user(&csr, cstat_range, sizeof(csr))) return -EFAULT;
/// if (is_file_hugepages(fd_file(f)))               return -EOPNOTSUPP;
/// if (!can_do_cachestat(fd_file(f)))               return -EPERM;
/// if (flags != 0)                                  return -EINVAL;
///
/// first_index = csr.off >> PAGE_SHIFT;
/// last_index  = csr.len == 0 ? ULONG_MAX
///                            : (csr.off + csr.len - 1) >> PAGE_SHIFT;
/// ```
///
/// Reports how much of a file range is in the page cache, so a program can
/// tell a read that will be served from memory from one that will hit the
/// device — and skip the readahead it can prove is unnecessary. The whole
/// value is in the answer being exact: an over-report makes a caller skip a
/// read it actually needed.
///
/// Note the ORDER, which is not the order the arguments appear in: the
/// descriptor, then the range copy, then the file type, then permission, and
/// only then `flags`. A caller passing both a bad pointer and a bad flag
/// gets -EFAULT, and the flag check being last is why.
///
/// `len == 0` means "to the end of the file", spelled as `ULONG_MAX` rather
/// than as the file size — a range past EOF simply has no pages in it.
pub(crate) fn sys_cachestat(ctx: &mut dyn TrapContext) {
    const PAGE_SHIFT: u32 = 12;
    let a = *ctx.args();
    let (fd, range_ptr, out_ptr, flags) = (a.arg0 as u32, a.arg1, a.arg2, a.arg3);

    let task = current_task_id();
    let Some(entry_ops) = crate::fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten()
    else {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
        return;
    };
    let mut raw = [0u8; 16];
    // SAFETY: `range_ptr` is the user `struct cachestat_range`; copy_from_user
    // range-validates it and brackets the 16-byte read.
    if unsafe { copy_from_user(&mut raw, range_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    let off = u64::from_ne_bytes(raw[0..8].try_into().unwrap());
    let len = u64::from_ne_bytes(raw[8..16].try_into().unwrap());

    // `can_do_cachestat`: writable descriptor, or ownership, or write
    // permission on the inode. Residency is a side channel about what
    // another user has read, which is why a read-only descriptor on someone
    // else's file is not enough.
    let (uid, gid) = entry_ops.owners();
    let writable = crate::fd::with_table(task, |t| {
        t.get(fd)
            .map(|e| e.status_flags & 0b11 == 1 || e.status_flags & 0b11 == 2)
    })
    .flatten()
    .unwrap_or(false);
    if !writable && !inode_owner_or_capable(task, uid, gid) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
        return;
    }
    if flags != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    let first = off >> PAGE_SHIFT;
    let last = if len == 0 {
        u64::MAX
    } else {
        off.saturating_add(len).saturating_sub(1) >> PAGE_SHIFT
    };
    // A filesystem with no page cache of its own reports all-zero, which is
    // the truth for it: nothing of the file is cached, so a caller should
    // read rather than assume.
    let cs = entry_ops
        .cachestat_range(first, last)
        .unwrap_or_default();

    let mut out = [0u8; 40];
    for (i, v) in [
        cs.nr_cache,
        cs.nr_dirty,
        cs.nr_writeback,
        cs.nr_evicted,
        cs.nr_recently_evicted,
    ]
    .iter()
    .enumerate()
    {
        out[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
    }
    // SAFETY: `out_ptr` is the user `struct cachestat`; copy_to_user
    // range-validates it and brackets the 40-byte write.
    if unsafe { copy_to_user(out_ptr, &out) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
