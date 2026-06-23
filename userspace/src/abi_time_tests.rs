//! Linux syscall ABI conformance — time group.
#![cfg(feature = "linux-compat")]
use crate::abi_test_support::*;

// Clock ids used across the time syscalls (mirrors the kernel-side
// constants in handlers.rs / posix_timer.rs).
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;

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
