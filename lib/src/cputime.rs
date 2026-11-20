//! Pure CPU-time arithmetic shared by the scheduler's accounting and the
//! `/proc` and syscall layers that report it (Linux `kernel/sched/cputime.c`,
//! `include/linux/jiffies.h`). Kept here, free of any clock or per-CPU
//! state, so it is host-tested.

/// `USER_HZ`: the clock-tick unit of `/proc/<pid>/stat`, `/proc/stat` and
/// `times(2)`.
pub const USER_HZ: u64 = 100;

/// `nsec_to_clock_t`: nanoseconds to `USER_HZ` ticks, truncating.
pub const fn ns_to_clock_t(ns: u64) -> u64 {
    ns / (1_000_000_000 / USER_HZ)
}

/// `clock_t_to_nsec`-style inverse of [`ns_to_clock_t`].
pub const fn clock_t_to_ns(ticks: u64) -> u64 {
    ticks.saturating_mul(1_000_000_000 / USER_HZ)
}

/// Wall cycles from `stamp` to `now` minus the interrupt cycles measured in
/// between (`irq_now - irq_stamp`): the part of a span that belongs to the
/// context it interrupted. Never negative; a `stamp` ahead of `now`
/// (cross-CPU clock skew) reads as an empty span.
pub const fn exclusive_span(now: u64, stamp: u64, irq_now: u64, irq_stamp: u64) -> u64 {
    now.saturating_sub(stamp)
        .saturating_sub(irq_now.saturating_sub(irq_stamp))
}

/// Linux `cputime_adjust`: scale a sampled `(stime, utime)` pair so the two
/// sum to the precise runtime `rtime`, without either reported field ever
/// decreasing across calls (`prev` holds the last reported `(utime, stime)`).
/// Returns `(utime, stime)`.
///
/// NARF's accounting is exact, so `stime + utime == rtime` and the scaling
/// is the identity; what remains is the monotonic filter for a reader that
/// combines fields sampled at slightly different instants.
pub fn cputime_adjust(stime: u64, utime: u64, rtime: u64, prev: &mut (u64, u64)) -> (u64, u64) {
    let (prev_utime, prev_stime) = *prev;
    // Never report less runtime than before.
    if prev_stime.saturating_add(prev_utime) >= rtime {
        return (prev_utime, prev_stime);
    }
    let mut stime_scaled = if stime == 0 {
        0
    } else if utime == 0 {
        rtime
    } else {
        // stime * rtime / (stime + utime), without overflow.
        ((stime as u128 * rtime as u128) / (stime as u128 + utime as u128)) as u64
    };
    // Neither field may go backwards: give the deficit to the other one.
    if stime_scaled < prev_stime {
        stime_scaled = prev_stime;
    }
    let mut utime_scaled = rtime - stime_scaled;
    if utime_scaled < prev_utime {
        utime_scaled = prev_utime;
        stime_scaled = rtime - utime_scaled;
    }
    *prev = (utime_scaled, stime_scaled);
    (utime_scaled, stime_scaled)
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn exclusive_span_removes_interrupt_cycles() {
        assert_eq!(exclusive_span(1_000, 400, 50, 20), 570);
        // Interrupt time can never make a span negative.
        assert_eq!(exclusive_span(1_000, 900, 500, 0), 0);
        // A stamp ahead of `now` (cross-CPU TSC skew) reads as empty.
        assert_eq!(exclusive_span(100, 200, 0, 0), 0);
    }

    #[test]
    fn clock_t_conversion_truncates_like_linux() {
        assert_eq!(ns_to_clock_t(0), 0);
        assert_eq!(ns_to_clock_t(9_999_999), 0);
        assert_eq!(ns_to_clock_t(10_000_000), 1);
        assert_eq!(ns_to_clock_t(1_000_000_000), USER_HZ);
        assert_eq!(ns_to_clock_t(u64::MAX), u64::MAX / 10_000_000);
        for ticks in [0, 1, 99, 100, 12_345] {
            assert_eq!(ns_to_clock_t(clock_t_to_ns(ticks)), ticks);
            assert_eq!(ns_to_clock_t(clock_t_to_ns(ticks) + 9_999_999), ticks);
        }
        assert_eq!(clock_t_to_ns(u64::MAX), u64::MAX);
    }

    #[test]
    fn cputime_adjust_scales_to_runtime() {
        let mut prev = (0, 0);
        // 3:1 user:system sampled split, 400 ns of precise runtime.
        assert_eq!(cputime_adjust(10, 30, 400, &mut prev), (300, 100));
        // Pure user and pure system runs keep all runtime on one side.
        let mut prev = (0, 0);
        assert_eq!(cputime_adjust(0, 7, 50, &mut prev), (50, 0));
        let mut prev = (0, 0);
        assert_eq!(cputime_adjust(7, 0, 50, &mut prev), (0, 50));
        // Exact inputs (NARF's case) come back unchanged.
        let mut prev = (0, 0);
        assert_eq!(cputime_adjust(123, 456, 579, &mut prev), (456, 123));
    }

    #[test]
    fn cputime_adjust_is_monotonic_per_field() {
        let mut prev = (0, 0);
        let mut last = (0, 0);
        for step in 1..2_000u64 {
            // A split that swings between system- and user-heavy phases.
            let stime = (step * 7) % 113 + step;
            let utime = (step * 13) % 97 + 2 * step;
            let rtime = step * 3;
            let out = cputime_adjust(stime, utime, rtime, &mut prev);
            assert!(
                out.0 >= last.0 && out.1 >= last.1,
                "field regressed at {step}"
            );
            assert_eq!(out.0 + out.1, rtime, "runtime not preserved at {step}");
            last = out;
        }
        // A stale, smaller runtime keeps the previous report.
        assert_eq!(cputime_adjust(1, 1, 3, &mut prev), last);
    }
}
