#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_timerfd_settime(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let flags = args.arg1 as u32;
    let new_value_ptr = args.arg2;
    let old_value_ptr = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    if new_value_ptr == 0 {
        ctx.set_return(fail);
        return;
    }
    // itimerspec is { interval: timespec, value: timespec } where
    // timespec = { tv_sec: i64, tv_nsec: i64 } = 16 B. Total 32 B.
    let mut buf = [0u8; 32];
    // SAFETY: `new_value_ptr` is the user itimerspec pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the 32-byte read.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_from_user(&mut buf, new_value_ptr) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let interval_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let interval_ns = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let value_sec = i64::from_le_bytes(buf[16..24].try_into().unwrap());
    let value_ns = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    let interval_total = (interval_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(interval_ns as u64);
    let value_total = (value_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(value_ns as u64);
    let now = narf_scheduler::narf_time::monotonic_ns();
    let next_fire = if value_total == 0 {
        0
    } else if (flags & 1) != 0 {
        value_total // TFD_TIMER_ABSTIME
    } else {
        now.saturating_add(value_total)
    };
    let tfd = match timerfd_arc_from_fd(task, fd) {
        Some(t) => t,
        None => {
            ctx.set_return(fail);
            return;
        }
    };

    let (rem_ns, int_ns) = tfd.current();
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
        // SAFETY: copy_to_user range-validates `old_value_ptr` and SMAP-brackets
        // the write of the 32-byte itimerspec `buf`.
        if unsafe { copy_to_user(old_value_ptr, &buf) }.is_err() {
            ctx.set_return(fail);
            return;
        }
    }

    tfd.arm(next_fire, interval_total);
    ctx.set_return(SyscallReturn::ok(0));
}
