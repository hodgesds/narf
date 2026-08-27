#[allow(unused_imports)]
use super::*;

/// `settimeofday(timeval*, timezone*)` — set wall-clock time from
/// `{ tv_sec: i64, tv_usec: i64 }`. arg0 may be null (no-op).
///
/// Error order follows `SYSCALL_DEFINE2(settimeofday)` (kernel/time/time.c,
/// Linux 7.0):
///   - a faulting `tv` → -EFAULT,
///   - `timeval_valid` (`tv_sec < 0` or `tv_usec` outside `[0, USEC_PER_SEC)`)
///     → -EINVAL.
///
/// `security_settime64` (→ `cap_settime`) rejects a caller without
/// CAP_SYS_TIME with -EPERM, and its POSITION is not where it reads: it
/// sits inside `do_sys_settimeofday64`, AFTER the syscall wrapper's EFAULT
/// and tv_usec-range EINVAL and after `timespec64_valid_settod`:
///
/// ```text
/// if (tv && !timespec64_valid_settod(tv))  return -EINVAL;
/// error = security_settime64(tv, tz);
/// if (error)                               return error;   /* -EPERM */
/// ```
///
/// So an unprivileged caller passing a bad pointer gets -EFAULT, and one
/// passing an out-of-range tv_usec gets -EINVAL — the permission answer
/// comes last. (An earlier note here claimed -EPERM came "before any of
/// this", which would have reported EPERM for a faulting pointer.)
pub(crate) fn sys_settimeofday(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let tv_ptr = args.arg0;
    // arg1 (timezone*) is ignored per Linux spec.
    if tv_ptr == 0 {
        // Null pointer → no-op, return success.
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // Read the timeval (two i64s) from user space.
    let mut kbuf = [0u8; 16];
    // SAFETY: `tv_ptr` is the user timeval pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the 16-byte read.
    if unsafe { copy_from_user(&mut kbuf, tv_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    let sec = i64::from_ne_bytes(kbuf[..8].try_into().unwrap());
    let usec = i64::from_ne_bytes(kbuf[8..].try_into().unwrap());
    // Validate: tv_usec must be in [0, 1_000_000).
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    // `security_settime64` — last of the checks, per the order above.
    if !capable(CAP_SYS_TIME) {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
        return;
    }
    // Convert µs → ns and set wall clock.
    let nsec = usec * 1_000; // µs → ns
    let target_ns = (sec as i128) * 1_000_000_000 + (nsec as i128);
    let mono_ns = narf_scheduler::narf_time::monotonic_ns() as i128;
    let offset_ns = (target_ns - mono_ns) as i64;
    narf_scheduler::narf_time::set_wall_offset_uncapped(offset_ns);
    crate::vdso::update_wall_offset(offset_ns);
    ctx.set_return(SyscallReturn::ok(0));
}
