#[allow(unused_imports)]
use super::*;

/// `sys_clock_settime(clock_id, *timespec)` — set CLOCK_REALTIME
/// by computing the wall-offset from the requested (sec, nsec) and
/// the current monotonic.
///
/// Error order follows `SYSCALL_DEFINE2(clock_settime)` (kernel/time/
/// posix-timers.c, Linux 7.0):
///   - an invalid or non-settable clock (`!kc || !kc->clock_set`) → -EINVAL,
///     checked BEFORE the timespec is read (so a bad clock beats a bad ptr),
///   - a NULL/faulting `tp` (`get_timespec64`) → -EFAULT,
///   - `timespec64_valid_settod` (`tv_sec < 0` or `tv_nsec` outside
///     `[0, NSEC_PER_SEC)`) → -EINVAL.
///
/// NARF only implements CLOCK_REALTIME as settable; every other clockid
/// (valid-but-unsettable like CLOCK_MONOTONIC, or entirely unknown) is the
/// same -EINVAL Linux returns.
///
/// LINUX-GAP: `security_settime64` rejects a caller without CAP_SYS_TIME with
/// -EPERM; NARF does not model that capability here.
pub(crate) fn sys_clock_settime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let id = args.arg0;
    let ts = args.arg1;
    // (1) Clock-id validation FIRST (Linux clockid_to_kclock / clock_set).
    if id != CLOCK_REALTIME {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    // (2) NULL/faulting timespec → -EFAULT.
    if ts == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    // Read the timespec (two i64s) from user space under the SMAP bracket.
    let mut kbuf = [0u8; 16];
    // SAFETY: `ts` is the user timespec pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the 16-byte read.
    if unsafe { copy_from_user(&mut kbuf, ts) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    // (3) Value validation → -EINVAL.
    let sec = i64::from_ne_bytes(kbuf[..8].try_into().unwrap());
    let nsec = i64::from_ne_bytes(kbuf[8..].try_into().unwrap());
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    let target_ns = (sec as i128) * 1_000_000_000 + (nsec as i128);
    let mono_ns = narf_scheduler::narf_time::monotonic_ns() as i128;
    let offset_ns = (target_ns - mono_ns) as i64;
    narf_scheduler::narf_time::set_wall_offset_uncapped(offset_ns);
    // Republish the offset to the vDSO vvar so __vdso_clock_gettime
    // (CLOCK_REALTIME) tracks the new wall time without a syscall.
    crate::vdso::update_wall_offset(offset_ns);
    ctx.set_return(SyscallReturn::ok(0));
}
