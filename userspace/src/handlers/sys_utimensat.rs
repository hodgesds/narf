#[allow(unused_imports)]
use super::*;

/// `utimensat(dirfd, path, timespec[2], flags)` — the modern entry musl
/// routes utime/utimes/futimens through. `times` NULL = both now;
/// tv_nsec may be UTIME_NOW / UTIME_OMIT per slot. `path` NULL with a real
/// `dirfd` is the futimens form (see [`do_utimes`]).
///
/// ```text
/// if (utimes) {
///         if (get_timespec64(&tstimes[0], &utimes[0]) ||
///             get_timespec64(&tstimes[1], &utimes[1])) return -EFAULT;
///         /* Nothing to do, we must not even check the path.  */
///         if (tstimes[0].tv_nsec == UTIME_OMIT &&
///             tstimes[1].tv_nsec == UTIME_OMIT) return 0;
/// }
/// return do_utimes(dfd, filename, utimes ? tstimes : NULL, flags);
/// ```
///
/// Out-of-range `tv_nsec` is NOT rejected here: `vfs_utimes` does that
/// after the lookup, so a bad descriptor is EBADF and a missing path ENOENT
/// even when the times are also invalid.
pub(crate) fn sys_utimensat(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let times = if a.arg2 == 0 {
        None
    } else {
        let mut buf = [0u8; 32];
        // SAFETY: non-zero user timespec[2] pointer; copy_from_user
        // range-validates and SMAP-brackets the 32-byte read.
        if unsafe { copy_from_user(&mut buf, a.arg2) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
        let word = |o: usize| i64::from_ne_bytes(buf[o..o + 8].try_into().unwrap());
        let times = [(word(0), word(8)), (word(16), word(24))];
        if times[0].1 == UTIME_OMIT && times[1].1 == UTIME_OMIT {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        Some(times)
    };
    do_utimes(ctx, a.arg0 as i64, a.arg1, times, a.arg3);
}
