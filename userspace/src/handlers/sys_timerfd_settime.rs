#[allow(unused_imports)]
use super::*;

/// `fs/timerfd.c::SYSCALL_DEFINE4(timerfd_settime, int, ufd, int, flags,
/// const struct __kernel_itimerspec __user *, utmr,
/// struct __kernel_itimerspec __user *, otmr)`.
///
/// ```text
/// if (get_itimerspec64(&new, utmr))
///         return -EFAULT;
/// ret = do_timerfd_settime(ufd, flags, &new, &old);
/// if (ret)
///         return ret;
/// if (otmr && put_itimerspec64(&old, otmr))
///         return -EFAULT;
/// ```
///
/// and `do_timerfd_settime`:
///
/// ```text
/// if ((flags & ~TFD_SETTIME_FLAGS) || !itimerspec64_valid(new))
///         return -EINVAL;
/// if (fd_empty(f))                        return -EBADF;
/// if (fd_file(f)->f_op != &timerfd_fops)  return -EINVAL;
/// if (isalarm(ctx) && !capable(CAP_WAKE_ALARM))
///         return -EPERM;
/// ```
///
/// The `utmr` read happens in the SYSCALL wrapper, before `do_timerfd_settime`
/// runs at all, so -EFAULT beats every other error: `timerfd_settime(-1, 0,
/// NULL, NULL)` is EFAULT, not EBADF. Only after that does the flags/value
/// validation run, and only then the descriptor.
///
/// Two things were missing entirely, both worse than a wrong errno because
/// they silently corrupted the timer:
///
///   * `flags` was never validated. Linux rejects anything outside
///     `TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET`; this read bit 0 and
///     discarded the rest, so an unsupported flag armed a timer with the
///     caller believing semantics it never got.
///   * the `itimerspec` was never validated. A negative `tv_sec`/`tv_nsec`
///     went through `(value_sec as u64).saturating_mul(1_000_000_000)`,
///     reinterpreting the sign bit as an enormous positive delay — a timer
///     that silently never fires instead of an EINVAL at the call.
pub(crate) fn sys_timerfd_settime(ctx: &mut dyn TrapContext) {
    const EFAULT: i64 = 14;
    const EINVAL: i64 = 22;
    /// `include/uapi/linux/timerfd.h`: TFD_TIMER_ABSTIME (1<<0) |
    /// TFD_TIMER_CANCEL_ON_SET (1<<1) — `TFD_SETTIME_FLAGS` in fs/timerfd.c.
    const TFD_SETTIME_FLAGS: u32 = 0x3;
    const TFD_TIMER_ABSTIME: u32 = 1 << 0;
    const NSEC_PER_SEC: i64 = 1_000_000_000;

    /// `include/linux/time64.h::timespec64_valid`:
    ///
    /// ```text
    /// if (ts->tv_sec < 0)                                  return false;
    /// if ((unsigned long)ts->tv_nsec >= NSEC_PER_SEC)      return false;
    /// ```
    ///
    /// The unsigned cast is why a NEGATIVE tv_nsec is rejected too: it
    /// wraps to a huge value, well past a second.
    fn timespec64_valid(sec: i64, nsec: i64) -> bool {
        sec >= 0 && (nsec as u64) < NSEC_PER_SEC as u64
    }

    let args = *ctx.args();
    // `int ufd`, `int flags` — both 32-bit.
    let fd = args.arg0 as u32;
    let flags = args.arg1 as u32;
    let new_value_ptr = args.arg2;
    let old_value_ptr = args.arg3;
    let task = current_task_id();

    // 1. `get_itimerspec64(&new, utmr)` — before anything else, including
    //    the descriptor. A null `utmr` fails range validation here.
    // itimerspec is { interval: timespec, value: timespec } where
    // timespec = { tv_sec: i64, tv_nsec: i64 } = 16 B. Total 32 B.
    let mut buf = [0u8; 32];
    // SAFETY: copy_from_user range-validates `new_value_ptr` (including the
    // null case) and SMAP-brackets the 32-byte read.
    if unsafe { copy_from_user(&mut buf, new_value_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    let interval_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let interval_ns = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let value_sec = i64::from_le_bytes(buf[16..24].try_into().unwrap());
    let value_ns = i64::from_le_bytes(buf[24..32].try_into().unwrap());

    // 2. `(flags & ~TFD_SETTIME_FLAGS) || !itimerspec64_valid(new)`.
    if flags & !TFD_SETTIME_FLAGS != 0
        || !timespec64_valid(interval_sec, interval_ns)
        || !timespec64_valid(value_sec, value_ns)
    {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }

    // 3. EBADF (no such descriptor) / EINVAL (not a timerfd).
    //
    // LINUX-GAP: the `isalarm(ctx) && !capable(CAP_WAKE_ALARM)` -EPERM arm
    // has no counterpart — NARF has no CLOCK_REALTIME_ALARM/BOOTTIME_ALARM
    // timerfd, so no descriptor can reach it.
    let tfd = match timerfd_arc_from_fd_checked(task, fd) {
        Ok(t) => t,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };

    // Both fields are now known non-negative and nsec-normalised, so the
    // widening to u64 cannot reinterpret a sign bit.
    let interval_total = (interval_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(interval_ns as u64);
    let value_total = (value_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value_ns as u64);
    let now = narf_scheduler::narf_time::monotonic_ns();
    let next_fire = if value_total == 0 {
        0
    } else if (flags & TFD_TIMER_ABSTIME) != 0 {
        value_total
    } else {
        now.saturating_add(value_total)
    };

    // `old` is snapshotted inside do_timerfd_settime BEFORE timerfd_setup
    // re-arms, but the `otmr` copy-out happens in the SYSCALL wrapper AFTER
    // do_timerfd_settime has already returned — so a faulting `otmr` reports
    // -EFAULT with the new timer ALREADY ARMED. Writing the old value before
    // arming would have made that EFAULT mean "nothing changed", and a caller
    // that retries after fixing its pointer would then re-arm a timer that was
    // in fact already running.
    let (rem_ns, int_ns) = tfd.current();
    tfd.arm(next_fire, interval_total);
    if old_value_ptr != 0 {
        let mut buf = [0u8; 32];
        let interval_sec = (int_ns / 1_000_000_000) as i64;
        let interval_nsec = (int_ns % 1_000_000_000) as i64;
        let value_sec = (rem_ns / 1_000_000_000) as i64;
        let value_nsec = (rem_ns % 1_000_000_000) as i64;
        buf[0..8].copy_from_slice(&interval_sec.to_le_bytes());
        buf[8..16].copy_from_slice(&interval_nsec.to_le_bytes());
        buf[16..24].copy_from_slice(&value_sec.to_le_bytes());
        buf[24..32].copy_from_slice(&value_nsec.to_le_bytes());
        // `if (otmr && put_itimerspec64(&old, otmr)) return -EFAULT;`
        // SAFETY: copy_to_user range-validates `old_value_ptr` and
        // SMAP-brackets the write of the 32-byte itimerspec `buf`.
        if unsafe { copy_to_user(old_value_ptr, &buf) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
            return;
        }
    }

    ctx.set_return(SyscallReturn::ok(0));
}
