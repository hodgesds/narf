#[allow(unused_imports)]
use super::*;

use crate::posix_timer::{
    CLOCKID_BOOTTIME, CLOCKID_BOOTTIME_ALARM, CLOCKID_MONOTONIC, CLOCKID_MONOTONIC_COARSE,
    CLOCKID_MONOTONIC_RAW, CLOCKID_PROCESS_CPUTIME_ID, CLOCKID_REALTIME, CLOCKID_REALTIME_ALARM,
    CLOCKID_REALTIME_COARSE, CLOCKID_TAI, CLOCKID_THREAD_CPUTIME_ID,
};

/// `kernel/time/posix-timers.c::SYSCALL_DEFINE2(clock_adjtime, const
/// clockid_t, which_clock, struct __kernel_timex __user *, utx)`.
///
/// ```text
/// if (copy_from_user(&ktx, utx, sizeof(ktx)))      return -EFAULT;
/// err = do_clock_adjtime(which_clock, &ktx);
/// if (err >= 0 && copy_to_user(utx, &ktx, sizeof(ktx)))  return -EFAULT;
/// return err;
/// ```
///
/// with
///
/// ```text
/// do_clock_adjtime(id, ktx):
///         kc = clockid_to_kclock(id);
///         if (!kc)           return -EINVAL;
///         if (!kc->clock_adj) return -EOPNOTSUPP;
/// ```
///
/// Only `clock_realtime` carries a `.clock_adj` (`posix_clock_realtime_adj`
/// in `posix_clocks[]`), so every other clock in the table — MONOTONIC,
/// BOOTTIME, TAI, the COARSE and RAW clocks, the ALARM clocks, the CPU-time
/// clocks — is EOPNOTSUPP, and only an id that names no clock at all is
/// EINVAL. This handler used to accept CLOCK_REALTIME, CLOCK_MONOTONIC,
/// CLOCK_BOOTTIME and CLOCK_TAI alike and report TIME_OK for all four, so a
/// caller probing which clocks it may discipline was told it could steer
/// three clocks that have no discipline interface.
pub(crate) fn sys_clock_adjtime(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let r = adjtimex_core(a.arg1, false, clock_adjtime_clock_ok(a.arg0 as i32));
    ctx.set_return(SyscallReturn::ok(r as u64));
}

/// Classify a `clockid_t` the way `clockid_to_kclock()` + `do_clock_adjtime()`
/// do. The shape mirrors `posix_timer::timer_create_clock_ok`.
fn clock_adjtime_clock_ok(clockid: i32) -> Result<(), i64> {
    // Negative ids: `clockid_to_kclock` splits them on the CLOCKFD encoding.
    // A dynamic-clock id (`/dev/ptpN`'s fd) reaches `clock_posix_dynamic`,
    // which DOES have a `.clock_adj` — but it resolves the fd through
    // `get_clock_desc`, and NARF has no PTP character devices, so no id of
    // that form can name a clock here: -EINVAL, as a bad fd gets there too.
    // Every other negative id is a CPU-time clock (`clock_posix_cpu`), which
    // has no `.clock_adj` at all — EOPNOTSUPP, whether or not the encoded pid
    // exists, because the lookup that would notice never runs.
    if clockid < 0 {
        return Err(if is_cpu_clock(clockid) {
            EOPNOTSUPP
        } else {
            EINVAL
        });
    }
    match clockid {
        // The one adjustable clock.
        CLOCKID_REALTIME => Ok(()),
        // In `posix_clocks[]`, no `.clock_adj`.
        CLOCKID_MONOTONIC
        | CLOCKID_PROCESS_CPUTIME_ID
        | CLOCKID_THREAD_CPUTIME_ID
        | CLOCKID_MONOTONIC_RAW
        | CLOCKID_REALTIME_COARSE
        | CLOCKID_MONOTONIC_COARSE
        | CLOCKID_BOOTTIME
        | CLOCKID_REALTIME_ALARM
        | CLOCKID_BOOTTIME_ALARM
        | CLOCKID_TAI => Err(EOPNOTSUPP),
        // Index 10 is a hole in `posix_clocks[]` and 12.. is past its end.
        // LINUX-GAP: Linux 6.17 added the CLOCK_AUX range (ids 16..=23,
        // `clock_aux`, CONFIG_POSIX_AUX_CLOCKS), which has a `.clock_adj`.
        // NARF has no auxiliary timekeepers, so those ids name no clock here
        // and answer EINVAL rather than steering one.
        _ => Err(EINVAL),
    }
}
