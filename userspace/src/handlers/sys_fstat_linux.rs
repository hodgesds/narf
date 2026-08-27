#[allow(unused_imports)]
use super::*;

/// `fs/stat.c::SYSCALL_DEFINE2(newfstat)` → `vfs_fstat` → `cp_new_stat`:
///
/// ```text
///     CLASS(fd_raw, f)(fd);
///     if (fd_empty(f))
///             return -EBADF;
///     ...
///     return copy_to_user(statbuf, &tmp, sizeof(tmp)) ? -EFAULT : 0;
/// ```
///
/// EBADF is decided before the destination is touched, so a stale descriptor
/// beats a bad pointer; this handler used to check the pointer first and
/// answer the bare -1 (= EPERM) for both. That matters because EBADF is the
/// one fstat error a caller is expected to recover from — glibc's stdio
/// re-probes a stream's descriptor with fstat and libraries that cache fds
/// across a fork/exec reopen on EBADF, while EPERM reads as "the file is
/// there and you may not look at it" and gets reported to the user verbatim.
pub(crate) fn sys_fstat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // Linux declares `unsigned int fd`; a negative fd wraps and misses the
    // table, which is EBADF either way.
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1 as *mut linux_compat::Stat;
    let task = current_task_id();
    let stat = fd::with_table(task, |t| {
        t.get(fd)
            .map(|e| (e.ops.stat(), e.ops.owners(), e.ops.rdev(), e.ops.ino()))
    });
    let (s, (uid, gid), rdev, ino) = match stat {
        Some(Some(tuple)) => tuple,
        _ => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
    };
    // A NULL statbuf is the cp_new_stat arm — reached only once the
    // descriptor has been accepted, exactly as in Linux.
    if out_ptr.is_null() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    let out = linux_stat_from_fs(s, uid, gid, rdev, ino);
    // SAFETY: `out` is a live repr(C) Stat; the slice spans exactly its size
    // and borrows it for the duration of the copy below.
    // SAFETY: Valid memory or trusted environment
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &out as *const linux_compat::Stat as *const u8,
            core::mem::size_of::<linux_compat::Stat>(),
        )
    };
    // SAFETY: `out_ptr` is the user Stat pointer (null-checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `bytes`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr as u64, bytes) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
