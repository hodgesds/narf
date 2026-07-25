//! Linux syscall ABI conformance — time group.
#![cfg(feature = "linux-compat")]
use crate::abi_test_support::*;

// Clock ids used across the time syscalls (mirrors the kernel-side
// constants in handlers.rs / posix_timer.rs).
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
const CLOCK_REALTIME_COARSE: u64 = 5;
const CLOCK_MONOTONIC_COARSE: u64 = 6;

// ── sysinfo(buf) ──────────────────────────────────────────────────────
// buf==0 → ok(-EFAULT); a valid 112-byte buffer → ok(0).

fn smoke_abi_time_sysinfo_pos() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 128];
        match call(Syscall::Sysinfo.raw(), a0(buf.as_mut_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("sysinfo with a valid buffer should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_sysinfo_pos);

fn smoke_abi_time_sysinfo_neg() -> TestResult {
    with_setup(|| {
        // NULL buffer → EFAULT (-14).
        match call(Syscall::Sysinfo.raw(), a0(0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("sysinfo(NULL) should return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_sysinfo_neg);

// ── adjtimex(timex) ───────────────────────────────────────────────────
// timex==0 → ok(-EFAULT); a valid timex buffer → ok(TIME_OK=0).

fn smoke_abi_time_adjtimex_pos() -> TestResult {
    with_setup(|| {
        // struct timex is large; a generously-sized zeroed buffer covers
        // every field the handler reads/writes (modes/freq/status/tick).
        let mut tx = [0u8; 256];
        match call(Syscall::Adjtimex.raw(), a0(tx.as_mut_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("adjtimex with a valid buffer should return TIME_OK (0)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_adjtimex_pos);

fn smoke_abi_time_adjtimex_neg() -> TestResult {
    with_setup(|| match call(Syscall::Adjtimex.raw(), a0(0)) {
        Some(v) if v == EFAULT => Ok(()),
        _ => Err("adjtimex(NULL) should return -EFAULT"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_adjtimex_neg);

// ── clock_adjtime(clockid, timex) ─────────────────────────────────────
// Accepted clock + valid buffer → ok(0); an unknown clockid → ok(-EINVAL).

fn smoke_abi_time_clock_adjtime_pos() -> TestResult {
    with_setup(|| {
        let mut tx = [0u8; 256];
        match call(
            Syscall::ClockAdjtime.raw(),
            a1(CLOCK_REALTIME, tx.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("clock_adjtime(CLOCK_REALTIME, buf) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_adjtime_pos);

fn smoke_abi_time_clock_adjtime_neg() -> TestResult {
    with_setup(|| {
        let mut tx = [0u8; 256];
        // clockid 99 is not one of REALTIME/MONOTONIC/BOOTTIME/TAI.
        match call(Syscall::ClockAdjtime.raw(), a1(99, tx.as_mut_ptr() as u64)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("clock_adjtime on an unknown clockid should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_adjtime_neg);

// ── times(tms) ────────────────────────────────────────────────────────
// A valid tms buffer → ok(ticks>=0). times(NULL) also succeeds (skips the
// struct write and returns the tick count) — matching Linux's times(NULL).

fn smoke_abi_time_times_pos() -> TestResult {
    with_setup(|| {
        let mut tms = [0u8; 32];
        match call(Syscall::Times.raw(), a0(tms.as_mut_ptr() as u64)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("times(buf) should return a non-negative tick count"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_times_pos);

fn smoke_abi_time_times_null_ok() -> TestResult {
    with_setup(|| {
        // out_ptr==0 skips the copy and still returns the tick count;
        // there is no easily-reachable error path for times() here.
        match call(Syscall::Times.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("times(NULL) should still return a tick count"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_times_null_ok);

// ── getrusage(who, rusage) ────────────────────────────────────────────
// out!=0 → ok(0); out==0 → ok(-1).

fn smoke_abi_time_getrusage_pos() -> TestResult {
    with_setup(|| {
        let mut ru = [0u8; 144];
        match call(Syscall::Getrusage.raw(), a1(0, ru.as_mut_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("getrusage(RUSAGE_SELF, buf) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_getrusage_pos);

fn smoke_abi_time_getrusage_neg() -> TestResult {
    with_setup(|| {
        // NULL out → the -1 sentinel.
        // LINUX-GAP: Linux returns -EFAULT here, NARF returns the -1 sentinel.
        match call(Syscall::Getrusage.raw(), a1(0, 0)) {
            Some(-1) => Ok(()),
            _ => Err("getrusage(_, NULL) should return the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_getrusage_neg);

// Regression: getrusage(RUSAGE_SELF) / times() must report the task's
// REAL accumulated CPU time, not wall-clock uptime. NARF used to return
// monotonic_ns() (uptime since boot) for every process, which inflated
// e.g. stress-ng's per-stressor usr-time ~17x. We assert the delta:
// accounting a known CPU slice moves ru_utime / tms.utime by ~that
// amount (uptime would instead drift by only the microseconds between
// the two reads). Delta-based so it's robust to any prior accumulation.
fn smoke_abi_time_cpu_accounting() -> TestResult {
    with_setup(|| {
        let read_ru_utime_ns = |who: i64| -> Option<u64> {
            let mut ru = [0u8; 144];
            match call(
                Syscall::Getrusage.raw(),
                a1(who as u64, ru.as_mut_ptr() as u64),
            ) {
                Some(0) => {
                    let sec = i64::from_ne_bytes(ru[0..8].try_into().unwrap());
                    let usec = i64::from_ne_bytes(ru[8..16].try_into().unwrap());
                    Some((sec as u64) * 1_000_000_000 + (usec as u64) * 1_000)
                }
                _ => None,
            }
        };
        // RUSAGE_SELF reflects accounted CPU time.
        let self_before = read_ru_utime_ns(0).ok_or("getrusage(RUSAGE_SELF) failed")?;
        crate::handlers::account_user_cpu_ns(300_000_000); // 300 ms
        let self_after = read_ru_utime_ns(0).ok_or("getrusage(RUSAGE_SELF) failed")?;
        if self_after.saturating_sub(self_before) < 250_000_000 {
            return Err("getrusage(RUSAGE_SELF).ru_utime must track accounted CPU, not uptime");
        }
        // times() tms.utime (field 0, ticks at 100 Hz) reflects the same.
        let mut tms = [0u8; 32];
        if call(Syscall::Times.raw(), a0(tms.as_mut_ptr() as u64))
            .filter(|v| *v >= 0)
            .is_none()
        {
            return Err("times(buf) failed");
        }
        let utime_ticks = i64::from_ne_bytes(tms[0..8].try_into().unwrap());
        if utime_ticks < 25 {
            // 300 ms ⇒ ≥ ~30 ticks; absolute lower bound tolerant of rounding.
            return Err("times().tms_utime must reflect accounted CPU time");
        }
        // RUSAGE_CHILDREN fold: charge a (distinct) child's accumulated CPU
        // time to the parent's children bucket. `99_001` stands in for a
        // reaped child; account_reaped_child returns its total and folds it.
        let child_before = read_ru_utime_ns(-1).ok_or("getrusage(RUSAGE_CHILDREN) failed")?;
        crate::handlers::__test_account_cpu_ns(99_001, 400_000_000);
        let folded = crate::handlers::account_reaped_child(FAKE_TASK, 99_001);
        if folded < 350_000_000 {
            return Err("account_reaped_child should return the child's accumulated CPU time");
        }
        let child_after = read_ru_utime_ns(-1).ok_or("getrusage(RUSAGE_CHILDREN) failed")?;
        if child_after.saturating_sub(child_before) < 350_000_000 {
            return Err("getrusage(RUSAGE_CHILDREN) must reflect reaped-child CPU time");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_cpu_accounting);

// ── sleep(ns) — NARF-native raw-nanosecond sleep ──────────────────────
// ns==0 returns immediately with 0. A non-zero ns busy-waits, so the
// only deterministic case is the zero-length sleep; there is no error path.

fn smoke_abi_time_sleep_pos() -> TestResult {
    with_setup(|| match call(Syscall::Sleep.raw(), a0(0)) {
        Some(0) => Ok(()),
        _ => Err("sleep(0) should return 0 immediately"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_sleep_pos);

// ── clock_gettime(clockid, timespec) ──────────────────────────────────
// Valid clock + aligned buffer → ok(0). NULL/misaligned buffer → invalid_op
// (a non-Ok NARF status; `call` returns None).

fn smoke_abi_time_clock_gettime_pos() -> TestResult {
    with_setup(|| {
        // 16-byte timespec; the array is 8-aligned so arg1 & 0x7 == 0.
        let mut ts = [0u64; 2];
        match call(
            Syscall::ClockGetTime.raw(),
            a1(CLOCK_MONOTONIC, ts.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("clock_gettime(MONOTONIC, buf) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_gettime_pos);

fn smoke_abi_time_clock_gettime_cpu_and_coarse_clocks() -> TestResult {
    with_setup(|| {
        for id in [
            CLOCK_PROCESS_CPUTIME_ID,
            CLOCK_THREAD_CPUTIME_ID,
            CLOCK_REALTIME_COARSE,
            CLOCK_MONOTONIC_COARSE,
        ] {
            let mut ts = [0u64; 2];
            if call(Syscall::ClockGetTime.raw(), a1(id, ts.as_mut_ptr() as u64)) != Some(0) {
                return Err("clock_gettime compatibility clock failed");
            }
            if ts[1] >= 1_000_000_000 {
                return Err("clock_gettime returned invalid tv_nsec");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_clock_gettime_cpu_and_coarse_clocks
);

fn smoke_abi_time_clock_gettime_neg() -> TestResult {
    with_setup(|| {
        // NULL buffer → invalid_op (None).
        // LINUX-GAP: Linux returns -EFAULT; NARF reports a non-Ok status.
        let r = call_raw(Syscall::ClockGetTime.raw(), a1(CLOCK_MONOTONIC, 0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("clock_gettime(_, NULL) should report invalid_op")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_gettime_neg);

// ── clock_getres(clockid, timespec) ───────────────────────────────────
// Valid clock (buffer may be NULL) → ok(0). Unknown clockid → invalid_op.

fn smoke_abi_time_clock_getres_pos() -> TestResult {
    with_setup(|| {
        let mut ts = [0u64; 2];
        match call(
            Syscall::ClockGetres.raw(),
            a1(CLOCK_REALTIME, ts.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("clock_getres(REALTIME, buf) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_getres_pos);

fn smoke_abi_time_clock_getres_neg() -> TestResult {
    with_setup(|| {
        // Unknown clockid → invalid_op (None).
        // LINUX-GAP: Linux returns -EINVAL; NARF reports a non-Ok status.
        let r = call_raw(Syscall::ClockGetres.raw(), a1(99, 0));
        if r.status == SyscallReturn::INVALID_OP {
            Ok(())
        } else {
            Err("clock_getres on an unknown clockid should report invalid_op")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_getres_neg);

// ── clock_settime(clockid, timespec) ──────────────────────────────────
// REALTIME + a sane timespec → ok(0). NULL ts → ok(-1).

fn smoke_abi_time_clock_settime_pos() -> TestResult {
    with_setup(|| {
        // {tv_sec: 1_700_000_000, tv_nsec: 0}.
        let ts: [i64; 2] = [1_700_000_000, 0];
        match call(
            Syscall::ClockSetTime.raw(),
            a1(CLOCK_REALTIME, ts.as_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("clock_settime(REALTIME, valid ts) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_settime_pos);

fn smoke_abi_time_clock_settime_neg() -> TestResult {
    with_setup(|| {
        // NULL timespec → the -1 sentinel.
        // LINUX-GAP: Linux returns -EFAULT; NARF returns the -1 sentinel.
        match call(Syscall::ClockSetTime.raw(), a1(CLOCK_REALTIME, 0)) {
            Some(-1) => Ok(()),
            _ => Err("clock_settime(_, NULL) should return the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_settime_neg);

// ── clock_nanosleep(clockid, flags, req, rem) ─────────────────────────
// A zero-length relative request returns immediately with 0 (no block).
// An unknown clockid → ok(-1).

fn smoke_abi_time_clock_nanosleep_pos() -> TestResult {
    with_setup(|| {
        // req = {0,0}: relative delta 0 → immediate return.
        let req: [i64; 2] = [0, 0];
        match call(
            Syscall::ClockNanosleep.raw(),
            a3(CLOCK_MONOTONIC, 0, req.as_ptr() as u64, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("clock_nanosleep with a zero request should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_nanosleep_pos);

fn smoke_abi_time_clock_nanosleep_neg() -> TestResult {
    with_setup(|| {
        let req: [i64; 2] = [0, 0];
        // Unknown clockid → -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL; NARF returns the -1 sentinel.
        match call(
            Syscall::ClockNanosleep.raw(),
            a3(99, 0, req.as_ptr() as u64, 0),
        ) {
            Some(-1) => Ok(()),
            _ => Err("clock_nanosleep on an unknown clockid should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_clock_nanosleep_neg);

// ── nanosleep(req, rem) — musl parses a `timespec*` in arg0 ────────────
// req={0,0} → immediate 0. NULL req → ok(-1).

fn smoke_abi_time_nanosleep_pos() -> TestResult {
    with_setup(|| {
        let req: [i64; 2] = [0, 0];
        match call(Syscall::Nanosleep.raw(), a1(req.as_ptr() as u64, 0)) {
            Some(0) => Ok(()),
            _ => Err("nanosleep({0,0}) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_nanosleep_pos);

fn smoke_abi_time_nanosleep_neg() -> TestResult {
    with_setup(|| {
        // NULL req → -1 sentinel.
        // LINUX-GAP: Linux returns -EFAULT; NARF returns the -1 sentinel.
        match call(Syscall::Nanosleep.raw(), a1(0, 0)) {
            Some(-1) => Ok(()),
            _ => Err("nanosleep(NULL, _) should return the -1 sentinel"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_nanosleep_neg);

// ── timer_create(clockid, sigevent, timerid) ──────────────────────────
// Valid clock + NULL sigevent (SIGEV_SIGNAL/SIGALRM default) + out → ok(0).
// Unknown clockid → ok(-1).

fn smoke_abi_time_timer_create_pos() -> TestResult {
    with_setup(|| {
        let mut id = [0u64; 1];
        match call(
            Syscall::TimerCreate.raw(),
            a2(CLOCK_MONOTONIC, 0, id.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("timer_create(MONOTONIC, NULL, out) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_create_pos);

fn smoke_abi_time_timer_create_neg() -> TestResult {
    with_setup(|| {
        let mut id = [0u64; 1];
        // Unknown clockid → -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL; NARF returns the -1 sentinel.
        match call(
            Syscall::TimerCreate.raw(),
            a2(99, 0, id.as_mut_ptr() as u64),
        ) {
            Some(-1) => Ok(()),
            _ => Err("timer_create on an unknown clockid should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_create_neg);

// Helper: create a POSIX timer and return its id, or Err.
fn make_timer() -> Result<u64, &'static str> {
    let mut id = [0u64; 1];
    match call(
        Syscall::TimerCreate.raw(),
        a2(CLOCK_MONOTONIC, 0, id.as_mut_ptr() as u64),
    ) {
        Some(0) => Ok(id[0]),
        _ => Err("timer_create setup failed"),
    }
}

// ── timer_settime(timerid, flags, new, old) ───────────────────────────
// A live timer + valid itimerspec → ok(0). NULL new → ok(-1).

fn smoke_abi_time_timer_settime_pos() -> TestResult {
    with_setup(|| {
        let id = make_timer()?;
        // itimerspec = { interval{0,0}, value{1,0} } (16 i64-bytes each).
        let new: [i64; 4] = [0, 0, 1, 0];
        match call(
            Syscall::TimerSettime.raw(),
            a3(id, 0, new.as_ptr() as u64, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("timer_settime on a live timer should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_settime_pos);

fn smoke_abi_time_timer_settime_neg() -> TestResult {
    with_setup(|| {
        let id = make_timer()?;
        // NULL new value → -1 sentinel.
        // LINUX-GAP: Linux returns -EFAULT; NARF returns the -1 sentinel.
        match call(Syscall::TimerSettime.raw(), a3(id, 0, 0, 0)) {
            Some(-1) => Ok(()),
            _ => Err("timer_settime(_, _, NULL, _) should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_settime_neg);

// ── timer_gettime(timerid, cur) ───────────────────────────────────────
// A live timer + valid out → ok(0). An unknown timerid → ok(-1).

fn smoke_abi_time_timer_gettime_pos() -> TestResult {
    with_setup(|| {
        let id = make_timer()?;
        let mut cur = [0i64; 4];
        match call(Syscall::TimerGettime.raw(), a1(id, cur.as_mut_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("timer_gettime on a live timer should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_gettime_pos);

fn smoke_abi_time_timer_gettime_neg() -> TestResult {
    with_setup(|| {
        let mut cur = [0i64; 4];
        // Timer id 0xdead was never created → -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL; NARF returns the -1 sentinel.
        match call(
            Syscall::TimerGettime.raw(),
            a1(0xdead, cur.as_mut_ptr() as u64),
        ) {
            Some(-1) => Ok(()),
            _ => Err("timer_gettime on an unknown id should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_gettime_neg);

// ── timer_delete(timerid) ─────────────────────────────────────────────
// Deleting a live timer → ok(0). An unknown timerid → ok(-1).

fn smoke_abi_time_timer_delete_pos() -> TestResult {
    with_setup(|| {
        let id = make_timer()?;
        match call(Syscall::TimerDelete.raw(), a0(id)) {
            Some(0) => Ok(()),
            _ => Err("timer_delete on a live timer should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_delete_pos);

fn smoke_abi_time_timer_delete_neg() -> TestResult {
    with_setup(|| {
        // Never-created id → -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL; NARF returns the -1 sentinel.
        match call(Syscall::TimerDelete.raw(), a0(0xdead)) {
            Some(-1) => Ok(()),
            _ => Err("timer_delete on an unknown id should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_delete_neg);

// ── setitimer(which, new, old) ────────────────────────────────────────
// which<=ITIMER_PROF + valid itimerval → ok(0). which>2 → ok(-1).

fn smoke_abi_time_setitimer_pos() -> TestResult {
    with_setup(|| {
        // ITIMER_REAL (0); itimerval = { interval{0,0}, value{0,0} } (disarm).
        let new: [i64; 4] = [0, 0, 0, 0];
        match call(Syscall::Setitimer.raw(), a2(0, new.as_ptr() as u64, 0)) {
            Some(0) => Ok(()),
            _ => Err("setitimer(ITIMER_REAL, valid, NULL) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_setitimer_pos);

fn smoke_abi_time_setitimer_neg() -> TestResult {
    with_setup(|| {
        let new: [i64; 4] = [0, 0, 0, 0];
        // which=5 is past ITIMER_PROF(2) → -1 sentinel.
        // LINUX-GAP: Linux returns -EINVAL; NARF returns the -1 sentinel.
        match call(Syscall::Setitimer.raw(), a2(5, new.as_ptr() as u64, 0)) {
            Some(-1) => Ok(()),
            _ => Err("setitimer on an invalid `which` should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_setitimer_neg);

// ── getitimer(which, cur) ─────────────────────────────────────────────
// which<=ITIMER_PROF + valid out → ok(0). out==0 → ok(-1).

fn smoke_abi_time_getitimer_pos() -> TestResult {
    with_setup(|| {
        let mut cur = [0i64; 4];
        match call(Syscall::Getitimer.raw(), a1(0, cur.as_mut_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("getitimer(ITIMER_REAL, buf) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_getitimer_pos);

fn smoke_abi_time_getitimer_neg() -> TestResult {
    with_setup(|| {
        // NULL out → -1 sentinel.
        // LINUX-GAP: Linux returns -EFAULT; NARF returns the -1 sentinel.
        match call(Syscall::Getitimer.raw(), a1(0, 0)) {
            Some(-1) => Ok(()),
            _ => Err("getitimer(_, NULL) should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_getitimer_neg);

// ── alarm(seconds) ────────────────────────────────────────────────────
// alarm(0) cancels any pending alarm and returns the previous remaining
// seconds (0 when none was armed). There is no error path.

fn smoke_abi_time_alarm_pos() -> TestResult {
    with_setup(|| {
        // No prior alarm armed → previous remaining is 0.
        match call(Syscall::Alarm.raw(), a0(0)) {
            Some(0) => Ok(()),
            _ => Err("alarm(0) with no prior alarm should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_alarm_pos);

fn smoke_abi_time_alarm_replace() -> TestResult {
    with_setup(|| {
        // Arm a long alarm, then alarm(0): the cancel must report the
        // previous alarm's remaining whole seconds (>= 1 for a 100s arm)
        // and disarm it.
        if call(Syscall::Alarm.raw(), a0(100)).is_none() {
            return Err("alarm(100) should succeed");
        }
        match call(Syscall::Alarm.raw(), a0(0)) {
            Some(v) if v >= 1 => Ok(()),
            _ => Err("alarm(0) after alarm(100) should return the remaining seconds"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_alarm_replace);

// ── timerfd_create(clockid, flags) ────────────────────────────────────
// Returns a fresh fd (>= 0). The fd table is always present in the
// harness, so there is no easily-reachable error path; both tests are
// positive (plain + O_CLOEXEC).

fn smoke_abi_time_timerfd_create_pos() -> TestResult {
    with_setup(
        || match call(Syscall::TimerfdCreate.raw(), a1(CLOCK_MONOTONIC, 0)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("timerfd_create should return a non-negative fd"),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_time_timerfd_create_pos);

fn smoke_abi_time_timerfd_create_cloexec() -> TestResult {
    with_setup(|| {
        // TFD_CLOEXEC = 0x80000.
        match call(Syscall::TimerfdCreate.raw(), a1(CLOCK_MONOTONIC, 0x80000)) {
            Some(fd) if fd >= 0 => Ok(()),
            _ => Err("timerfd_create(CLOEXEC) should return a non-negative fd"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timerfd_create_cloexec);

// Helper: open a timerfd and return its fd, or Err.
fn make_timerfd() -> Result<u64, &'static str> {
    match call(Syscall::TimerfdCreate.raw(), a1(CLOCK_MONOTONIC, 0)) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("timerfd_create setup failed"),
    }
}

// ── timerfd_settime(fd, flags, new, old) ──────────────────────────────
// A real timerfd + valid itimerspec → ok(0). NULL new → ok(-1).

fn smoke_abi_time_timerfd_settime_pos() -> TestResult {
    with_setup(|| {
        let fd = make_timerfd()?;
        // itimerspec = { interval{0,0}, value{1,0} }.
        let new: [i64; 4] = [0, 0, 1, 0];
        match call(
            Syscall::TimerfdSettime.raw(),
            a3(fd, 0, new.as_ptr() as u64, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("timerfd_settime on a real fd should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timerfd_settime_pos);

fn smoke_abi_time_timerfd_settime_neg() -> TestResult {
    with_setup(|| {
        let fd = make_timerfd()?;
        // NULL new value → -1 sentinel (checked before the fd lookup).
        // LINUX-GAP: Linux returns -EFAULT; NARF returns the -1 sentinel.
        match call(Syscall::TimerfdSettime.raw(), a3(fd, 0, 0, 0)) {
            Some(-1) => Ok(()),
            _ => Err("timerfd_settime(_, _, NULL, _) should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timerfd_settime_neg);

// ── timerfd_gettime(fd, curr) ─────────────────────────────────────────
// A real timerfd + valid out → ok(0). A bad fd → ok(-1).

fn smoke_abi_time_timerfd_gettime_pos() -> TestResult {
    with_setup(|| {
        let fd = make_timerfd()?;
        let mut cur = [0i64; 4];
        match call(
            Syscall::TimerfdGettime.raw(),
            a1(fd, cur.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("timerfd_gettime on a real fd should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timerfd_gettime_pos);

fn smoke_abi_time_timerfd_gettime_neg() -> TestResult {
    with_setup(|| {
        let mut cur = [0i64; 4];
        // fd 4242 was never opened → -1 sentinel.
        // LINUX-GAP: Linux returns -EBADF; NARF returns the -1 sentinel.
        match call(
            Syscall::TimerfdGettime.raw(),
            a1(4242, cur.as_mut_ptr() as u64),
        ) {
            Some(-1) => Ok(()),
            _ => Err("timerfd_gettime on a bad fd should return -1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timerfd_gettime_neg);

// ── gettimeofday(timeval, timezone) ───────────────────────────────────
// Valid timeval* → ok(0) with a normalized, non-regressing timeval.
// timezone* is ignored (NARF follows Linux).

fn smoke_abi_time_gettimeofday_pos() -> TestResult {
    with_setup(|| {
        let mut tv = [0i64; 2];
        match call(Syscall::Gettimeofday.raw(), a1(tv.as_mut_ptr() as u64, 0)) {
            Some(0) => {
                // An unseeded wall clock may legitimately still be in epoch
                // second zero when fast aarch64 CI reaches this test.
                let tv_sec = tv[0];
                let tv_usec = tv[1];
                if tv_sec < 0 {
                    return Err("gettimeofday tv_sec should be non-negative");
                }
                if !(0..1_000_000).contains(&tv_usec) {
                    return Err("gettimeofday tv_usec must be in [0, 1_000_000)");
                }
                let first = (tv_sec, tv_usec);
                match call(Syscall::Gettimeofday.raw(), a1(tv.as_mut_ptr() as u64, 0)) {
                    Some(0) if (tv[0], tv[1]) >= first => {}
                    Some(0) => return Err("gettimeofday moved backwards"),
                    _ => return Err("second gettimeofday call failed"),
                }
                Ok(())
            }
            _ => Err("gettimeofday with a valid buffer should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_gettimeofday_pos);

fn smoke_abi_time_gettimeofday_null() -> TestResult {
    with_setup(|| {
        // NULL timeval* is allowed; just return 0.
        match call(Syscall::Gettimeofday.raw(), a1(0, 0)) {
            Some(0) => Ok(()),
            _ => Err("gettimeofday(NULL, NULL) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_gettimeofday_null);

// ── settimeofday(timeval, timezone) ───────────────────────────────────
// Valid timeval* → ok(0). NULL timeval* → ok(0) (no-op).

fn smoke_abi_time_settimeofday_pos() -> TestResult {
    with_setup(|| {
        // First read the current time.
        let mut tv_get = [0i64; 2];
        call(
            Syscall::Gettimeofday.raw(),
            a1(tv_get.as_mut_ptr() as u64, 0),
        )
        .ok_or("gettimeofday failed")?;
        // Set the same time back.
        let tv_set = tv_get;
        match call(Syscall::Settimeofday.raw(), a1(tv_set.as_ptr() as u64, 0)) {
            Some(0) => Ok(()),
            _ => Err("settimeofday with a valid buffer should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_settimeofday_pos);

fn smoke_abi_time_settimeofday_null() -> TestResult {
    with_setup(|| {
        // NULL timeval* → no-op, return 0.
        match call(Syscall::Settimeofday.raw(), a1(0, 0)) {
            Some(0) => Ok(()),
            _ => Err("settimeofday(NULL, NULL) should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_settimeofday_null);

// ── time(time_t*) ────────────────────────────────────────────────────────
// Returns seconds; if arg0 non-null, also stores there.

#[cfg(target_arch = "x86_64")]
fn smoke_abi_time_time_pos() -> TestResult {
    with_setup(|| {
        let mut time_buf = [0i64; 1];
        let ret =
            call(Syscall::Time.raw(), a0(time_buf.as_mut_ptr() as u64)).ok_or("time() failed")?;
        // Return value should match what was stored.
        if ret as i64 != time_buf[0] {
            return Err("time() return value should match stored value");
        }
        // Seconds should be non-zero and reasonable (after 1970).
        if ret == 0 {
            return Err("time() should return non-zero seconds since epoch");
        }
        Ok(())
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_time_time_pos);

#[cfg(target_arch = "x86_64")]
fn smoke_abi_time_time_null() -> TestResult {
    with_setup(|| {
        // NULL pointer is allowed; just return seconds.
        let ret = call(Syscall::Time.raw(), a0(0)).ok_or("time(NULL) failed")?;
        if ret == 0 {
            return Err("time(NULL) should return non-zero seconds");
        }
        Ok(())
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("syscall_abi", smoke_abi_time_time_null);

// ── ioprio_set / ioprio_get ──────────────────────────────────────────────
// ioprio_set stores a value; ioprio_get retrieves it or returns the default.

fn smoke_abi_time_ioprio_roundtrip() -> TestResult {
    with_setup(|| {
        // ioprio_set(1, 0, 0x1234) → stores 0x1234
        call(Syscall::IoprioSet.raw(), a2(1, 0, 0x1234)).ok_or("ioprio_set failed")?;
        // ioprio_get(1, 0) → returns 0x1234
        let val = call(Syscall::IoprioGet.raw(), a1(1, 0)).ok_or("ioprio_get failed")?;
        if val != 0x1234 {
            return Err("ioprio_get should return the set value");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_ioprio_roundtrip);

fn smoke_abi_time_ioprio_default() -> TestResult {
    with_setup(|| {
        // ioprio_get on an unset (which, who) returns the default.
        // Default is (IOPRIO_CLASS_BE=2 << 13) | 4 = 0x4004.
        let val = call(Syscall::IoprioGet.raw(), a1(1, 9999)).ok_or("ioprio_get failed")?;
        let default = (2i64 << 13) | 4;
        if val != default {
            return Err("ioprio_get on unset entry should return default (0x4004)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_ioprio_default);
