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
/// LINUX-GAP: `security_settime64` rejects a caller without CAP_SYS_TIME with
/// -EPERM before any of this; NARF does not model that capability here and
/// lets any task set the clock.
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
    // Convert µs → ns and set wall clock.
    let nsec = usec * 1_000; // µs → ns
    let target_ns = (sec as i128) * 1_000_000_000 + (nsec as i128);
    let mono_ns = narf_scheduler::narf_time::monotonic_ns() as i128;
    let offset_ns = (target_ns - mono_ns) as i64;
    narf_scheduler::narf_time::set_wall_offset_uncapped(offset_ns);
    crate::vdso::update_wall_offset(offset_ns);
    ctx.set_return(SyscallReturn::ok(0));
}
