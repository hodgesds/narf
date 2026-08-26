#[allow(unused_imports)]
use super::*;

/// NARF-shape `fstat` (a 64-byte `StatBuf` instead of Linux's 144-byte
/// `struct stat`).
///
/// SHADOWED under `linux-compat`: `install_core_syscalls` installs this on
/// `Syscall::Fstat` early, then re-installs [`sys_fstat_linux`] over the same
/// slot, so only the `--no-default-features` (non-linux-compat) build reaches
/// this body. The errnos still follow `fs/stat.c::SYSCALL_DEFINE2(newfstat)`
/// → `vfs_fstat`: `fd_empty(f)` → -EBADF first, then `cp_new_stat`'s
/// `copy_to_user` → -EFAULT. Both used to be the bare -1, which libc reads as
/// EPERM.
pub(crate) fn sys_fstat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1 as *mut StatBuf;
    let task = current_task_id();
    let stat = fd::with_table(task, |t| {
        t.get(fd).map(|e| StatBuf::from_stat(e.ops.stat()))
    });
    let stat = match stat {
        Some(Some(s)) => s,
        _ => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // -EBADF
            return;
        }
    };
    // The destination is only inspected once the fd is known good, so a
    // stale descriptor reports EBADF rather than EFAULT.
    if out_ptr.is_null() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    // SAFETY: same contract as sys_stat above.
    let stat_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &stat as *const StatBuf as *const u8,
            core::mem::size_of::<StatBuf>(),
        )
    };
    // SAFETY: `out_ptr` is the user StatBuf pointer (null-checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `stat_bytes`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr as u64, stat_bytes) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
