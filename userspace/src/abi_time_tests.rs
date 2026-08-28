//! Linux syscall ABI conformance — time group.
use crate::abi_test_support::*;

// Clock ids used across the time syscalls (mirrors the kernel-side
// constants in handlers.rs / posix_timer.rs).
const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
const CLOCK_REALTIME_COARSE: u64 = 5;
const CLOCK_MONOTONIC_COARSE: u64 = 6;

/// SIGALRM — `timer_create`'s default signo when `sigevent` is NULL.
const SIGALRM_SIGNO: i32 = 14;

/// A canonical-but-unmapped user address: non-null, so it passes any
/// null check and only fails when actually accessed. Distinguishes the
/// EFAULT arms from the EINVAL ones.
const BAD_PTR: u64 = 0x0001_0000_0000_0000;

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
        // out_ptr==0 skips the copy and still returns the tick count.
        match call(Syscall::Times.raw(), a0(0)) {
            Some(v) if v >= 0 => Ok(()),
            _ => Err("times(NULL) should still return a tick count"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_times_null_ok);

fn smoke_abi_time_times_efault() -> TestResult {
    with_setup(|| {
        // A non-NULL but faulting tbuf → -EFAULT (copy_to_user of struct tms),
        // matching Linux SYSCALL_DEFINE1(times).
        if call(Syscall::Times.raw(), a0(u64::MAX)) != Some(EFAULT) {
            return Err("times(faulting buf) should return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_times_efault);

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
        // An unknown `who` (not SELF/CHILDREN/THREAD) → -EINVAL, checked
        // before `ru` is touched, so it beats even a NULL ru.
        if call(Syscall::Getrusage.raw(), a1(99, 0)) != Some(EINVAL) {
            return Err("getrusage(bad who, _) should return -EINVAL");
        }
        // A valid `who` but a NULL/faulting ru → -EFAULT.
        if call(Syscall::Getrusage.raw(), a1(0, 0)) != Some(EFAULT) {
            return Err("getrusage(RUSAGE_SELF, NULL) should return -EFAULT");
        }
        if call(Syscall::Getrusage.raw(), a1(0, u64::MAX)) != Some(EFAULT) {
            return Err("getrusage(RUSAGE_SELF, faulting) should return -EFAULT");
        }
        Ok(())
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
        // LINUX ABI: a NULL/faulting timespec pointer → -EFAULT (previously
        // folded to a non-Ok InvalidOp status). Linux never checks alignment.
        let r = call(Syscall::ClockGetTime.raw(), a1(CLOCK_MONOTONIC, 0));
        if r == Some(EFAULT) {
            Ok(())
        } else {
            Err("clock_gettime(_, NULL) must return -EFAULT")
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
        // A non-settable clock is -EINVAL, and it is checked BEFORE the
        // timespec, so a bad clock beats even a NULL ptr (Linux
        // clockid_to_kclock/clock_set precede get_timespec64).
        if call(Syscall::ClockSetTime.raw(), a1(CLOCK_MONOTONIC, 0)) != Some(EINVAL) {
            return Err("clock_settime(CLOCK_MONOTONIC, _) should return -EINVAL");
        }
        // Settable clock but a NULL/faulting timespec → -EFAULT.
        if call(Syscall::ClockSetTime.raw(), a1(CLOCK_REALTIME, 0)) != Some(EFAULT) {
            return Err("clock_settime(REALTIME, NULL) should return -EFAULT");
        }
        if call(Syscall::ClockSetTime.raw(), a1(CLOCK_REALTIME, u64::MAX)) != Some(EFAULT) {
            return Err("clock_settime(REALTIME, faulting ts) should return -EFAULT");
        }
        // Out-of-range tv_nsec → -EINVAL.
        let bad: [i64; 2] = [1, 1_000_000_000];
        if call(
            Syscall::ClockSetTime.raw(),
            a1(CLOCK_REALTIME, bad.as_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("clock_settime with tv_nsec >= 1e9 should return -EINVAL");
        }
        Ok(())
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
        // `clockid_to_kclock(which_clock)` returning NULL is -EINVAL.
        match call(
            Syscall::ClockNanosleep.raw(),
            a3(99, 0, req.as_ptr() as u64, 0),
        ) {
            Some(-22) => Ok(()),
            Some(-1) => Err("clock_nanosleep(bad clockid) still returns the -1/EPERM sentinel"),
            _ => Err("clock_nanosleep on an unknown clockid should be -EINVAL"),
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
        // `get_timespec64(&t, rqtp)` on a NULL rqtp is -EFAULT.
        match call(Syscall::Nanosleep.raw(), a1(0, 0)) {
            Some(-14) => Ok(()),
            Some(-1) => Err("nanosleep(NULL) still returns the -1/EPERM sentinel"),
            _ => Err("nanosleep(NULL, _) should be -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_nanosleep_neg);

// ═════════════════════════════════════════════════════════════════════
// POSIX interval timers — `kernel/time/posix-timers.c`, `itimer.c`
// ═════════════════════════════════════════════════════════════════════
//
// Every handler in `posix_timer.rs` used to answer a bare `-1`, which a
// libc stub turns into errno 1 = EPERM. These smokes pin the errnos
// Linux actually returns AND the order the checks run in, because Linux
// fixes which error wins when several apply — a faulting `sigevent`
// beats a bad clockid in `timer_create`, but a stale timerid beats a
// faulting output buffer in `timer_gettime`.
//
// Clock ids `timer_create` classifies (`posix_clocks[]`). 4/5/6 are in
// the table but carry no `.timer_create` → EOPNOTSUPP; 10 is a hole in
// the table and >= 12 is past its end → EINVAL.
const CLOCK_MONOTONIC_RAW: u64 = 4;
const CLOCK_BOOTTIME: u64 = 7;
const CLOCK_TABLE_HOLE: u64 = 10;

// `sigev_notify` values. THREAD_ID is a modifier ORed onto SIGEV_SIGNAL,
// which is how glibc implements SIGEV_THREAD.
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD_ID: i32 = 4;
/// glibc's SIGRTMIN. `timer_create` must accept it: glibc's SIGEV_THREAD
/// timers ask for exactly this signo.
const SIGRTMIN: i32 = 34;

/// A pointer that is non-NULL and guaranteed to fail `validate_user_range`
/// (the range end overflows), so the handler must report EFAULT.
const FAULTING: u64 = u64::MAX;

/// Build the 16 bytes of `struct sigevent` the handler reads:
/// `sigev_value` (8 B) then `sigev_signo` (4 B) then `sigev_notify` (4 B).
fn sigevent(signo: i32, notify: i32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[8..12].copy_from_slice(&signo.to_le_bytes());
    b[12..16].copy_from_slice(&notify.to_le_bytes());
    b
}

// ── timer_create(clockid, sigevent, timerid) ──────────────────────────

/// Positive paths, so a later tightening of the error arms cannot
/// silently turn a working `timer_create` into a failure: every clock
/// NARF can actually arm, the NULL-sigevent default (SIGEV_SIGNAL +
/// SIGALRM), and the sigevent shapes glibc/musl really emit.
fn smoke_abi_time_timer_create_pos() -> TestResult {
    with_setup(|| {
        let mut id = [0u64; 1];
        let out = id.as_mut_ptr() as u64;
        for clk in [CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME] {
            if call(Syscall::TimerCreate.raw(), a2(clk, 0, out)) != Some(0) {
                return Err("timer_create(<armable clock>, NULL, out) should return 0");
            }
        }
        // `clockid_t` is `int`: only the low 32 bits reach the kernel, so
        // garbage in the upper half still names CLOCK_MONOTONIC.
        if call(
            Syscall::TimerCreate.raw(),
            a2((1u64 << 32) | CLOCK_MONOTONIC, 0, out),
        ) != Some(0)
        {
            return Err("timer_create must truncate clockid to 32 bits");
        }
        // Explicit sigevents. SIGRTMIN matters: glibc's SIGEV_THREAD
        // rewrites to SIGEV_SIGNAL|SIGEV_THREAD_ID with signo=SIGRTMIN,
        // and the old `signum >= 32` cap rejected every one of them.
        for ev in [
            sigevent(SIGALRM_SIGNO, SIGEV_SIGNAL),
            sigevent(SIGRTMIN, SIGEV_SIGNAL),
            sigevent(SIGRTMIN, SIGEV_SIGNAL | SIGEV_THREAD_ID),
            sigevent(0, SIGEV_NONE),
        ] {
            if call(
                Syscall::TimerCreate.raw(),
                a2(CLOCK_MONOTONIC, ev.as_ptr() as u64, out),
            ) != Some(0)
            {
                return Err("timer_create with a valid sigevent should return 0");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_create_pos);

/// `do_timer_create`: `if (!kc) return -EINVAL;` for a clockid that is not
/// in `posix_clocks[]` at all.
fn smoke_abi_time_timer_create_unknown_clock_einval() -> TestResult {
    with_setup(|| {
        let mut id = [0u64; 1];
        let out = id.as_mut_ptr() as u64;
        for clk in [99, CLOCK_TABLE_HOLE, 12] {
            if call(Syscall::TimerCreate.raw(), a2(clk, 0, out)) != Some(EINVAL) {
                return Err("timer_create on a clockid outside posix_clocks[] should be -EINVAL");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timer_create_unknown_clock_einval
);

/// `do_timer_create`: `if (!kc->timer_create) return -EOPNOTSUPP;`.
/// CLOCK_MONOTONIC_RAW and the _COARSE clocks are real clocks with no
/// timer support — NARF used to *accept* MONOTONIC_RAW and hand back a
/// timer Linux would have refused. The CPU-time clocks are a documented
/// NARF gap reported with the same "clock exists, timers do not" errno.
fn smoke_abi_time_timer_create_no_timer_clock_eopnotsupp() -> TestResult {
    with_setup(|| {
        let mut id = [0u64; 1];
        let out = id.as_mut_ptr() as u64;
        for clk in [
            CLOCK_MONOTONIC_RAW,
            CLOCK_REALTIME_COARSE,
            CLOCK_MONOTONIC_COARSE,
            CLOCK_PROCESS_CPUTIME_ID,
            CLOCK_THREAD_CPUTIME_ID,
        ] {
            if call(Syscall::TimerCreate.raw(), a2(clk, 0, out)) != Some(EOPNOTSUPP) {
                return Err("timer_create on a clock with no timer support should be -EOPNOTSUPP");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timer_create_no_timer_clock_eopnotsupp
);

/// ORDER: `sys_timer_create` copies the sigevent in the syscall wrapper,
/// *before* `do_timer_create` looks at the clockid. So a faulting
/// sigevent wins over a bad clock (EFAULT, not EINVAL) — while the
/// output pointer is not touched until the very end and loses to both.
fn smoke_abi_time_timer_create_order() -> TestResult {
    with_setup(|| {
        let mut id = [0u64; 1];
        let out = id.as_mut_ptr() as u64;
        // Faulting sigevent + unknown clock → the sigevent copy wins.
        if call(Syscall::TimerCreate.raw(), a2(99, FAULTING, out)) != Some(EFAULT) {
            return Err("timer_create(bad clock, faulting evp, _) should be -EFAULT");
        }
        // Bad clock + NULL out → the clock check wins.
        if call(Syscall::TimerCreate.raw(), a2(99, 0, 0)) != Some(EINVAL) {
            return Err("timer_create(bad clock, NULL, NULL) should be -EINVAL");
        }
        // Bad sigevent + NULL out → the sigevent check wins.
        let ev = sigevent(0, SIGEV_SIGNAL);
        if call(
            Syscall::TimerCreate.raw(),
            a2(CLOCK_MONOTONIC, ev.as_ptr() as u64, 0),
        ) != Some(EINVAL)
        {
            return Err("timer_create(_, bad sigevent, NULL) should be -EINVAL");
        }
        // Everything else valid → the output copy is what fails.
        for bad_out in [0, FAULTING] {
            if call(Syscall::TimerCreate.raw(), a2(CLOCK_MONOTONIC, 0, bad_out)) != Some(EFAULT) {
                return Err("timer_create(_, _, unwritable out) should be -EFAULT");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_create_order);

/// `good_sigevent()`: `sigev_signo <= 0 || sigev_signo > SIGRTMAX(64)`
/// and any `sigev_notify` outside its switch → -EINVAL.
fn smoke_abi_time_timer_create_bad_sigevent_einval() -> TestResult {
    with_setup(|| {
        let mut id = [0u64; 1];
        let out = id.as_mut_ptr() as u64;
        let bad = [
            sigevent(0, SIGEV_SIGNAL),  // signo == 0
            sigevent(-1, SIGEV_SIGNAL), // signo < 0
            sigevent(65, SIGEV_SIGNAL), // signo > SIGRTMAX
            sigevent(SIGRTMIN, 3),      // notify not in the switch
            sigevent(SIGRTMIN, 5),      // SIGEV_NONE|THREAD_ID: not a case
            sigevent(SIGRTMIN, 6),      // SIGEV_THREAD|THREAD_ID: not a case
            sigevent(SIGRTMIN, 99),     // garbage
        ];
        for ev in bad {
            if call(
                Syscall::TimerCreate.raw(),
                a2(CLOCK_MONOTONIC, ev.as_ptr() as u64, out),
            ) != Some(EINVAL)
            {
                return Err("timer_create with a rejected sigevent should be -EINVAL");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timer_create_bad_sigevent_einval
);

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

// Helper: a timerid that named a real timer and no longer does.
fn stale_timer() -> Result<u64, &'static str> {
    let id = make_timer()?;
    match call(Syscall::TimerDelete.raw(), a0(id)) {
        Some(0) => Ok(id),
        _ => Err("timer_delete setup failed"),
    }
}

// ── timer_settime(timerid, flags, new, old) ───────────────────────────

fn smoke_abi_time_timer_settime_pos() -> TestResult {
    with_setup(|| {
        let id = make_timer()?;
        // itimerspec = { interval{0,0}, value{1,0} } (16 i64-bytes each).
        let new: [i64; 4] = [0, 0, 1, 0];
        let mut old = [0i64; 4];
        if call(
            Syscall::TimerSettime.raw(),
            a3(id, 0, new.as_ptr() as u64, 0),
        ) != Some(0)
        {
            return Err("timer_settime on a live timer should return 0");
        }
        // With an old-value buffer, and with TIMER_ABSTIME set.
        if call(
            Syscall::TimerSettime.raw(),
            a3(id, 0, new.as_ptr() as u64, old.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("timer_settime with an old-value buffer should return 0");
        }
        if call(
            Syscall::TimerSettime.raw(),
            a3(id, 1, new.as_ptr() as u64, 0),
        ) != Some(0)
        {
            return Err("timer_settime(TIMER_ABSTIME) should return 0");
        }
        // Linux never validates `flags`: `common_timer_set` only tests
        // TIMER_ABSTIME and ignores every other bit. Unknown bits must
        // NOT start failing.
        if call(
            Syscall::TimerSettime.raw(),
            a3(id, 0xF0, new.as_ptr() as u64, 0),
        ) != Some(0)
        {
            return Err("timer_settime must ignore unknown flag bits, like Linux");
        }
        // Disarm.
        let off: [i64; 4] = [0, 0, 0, 0];
        if call(
            Syscall::TimerSettime.raw(),
            a3(id, 0, off.as_ptr() as u64, 0),
        ) != Some(0)
        {
            return Err("timer_settime disarm should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_settime_pos);

/// `sys_timer_settime`: `if (!new_setting) return -EINVAL;` — Linux
/// rejects the missing argument *before* trying to read it, so this is
/// EINVAL and NOT EFAULT. That distinction is the whole point: EFAULT
/// sends a caller inspecting its memory map for a pointer it never
/// passed.
fn smoke_abi_time_timer_settime_null_new_einval() -> TestResult {
    with_setup(|| {
        let id = make_timer()?;
        if call(Syscall::TimerSettime.raw(), a3(id, 0, 0, 0)) != Some(EINVAL) {
            return Err("timer_settime(_, _, NULL, _) should be -EINVAL, not -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_settime_null_new_einval);

/// ORDER + errnos for the remaining arms: the `new` copy (EFAULT) runs
/// before the timer lookup (EINVAL), and `timespec64_valid` (EINVAL)
/// runs before it too.
fn smoke_abi_time_timer_settime_neg() -> TestResult {
    with_setup(|| {
        let live = make_timer()?;
        let stale = stale_timer()?;
        let new: [i64; 4] = [0, 0, 1, 0];
        // Faulting `new` beats a stale timerid.
        if call(Syscall::TimerSettime.raw(), a3(stale, 0, FAULTING, 0)) != Some(EFAULT) {
            return Err("timer_settime(stale, _, faulting new, _) should be -EFAULT");
        }
        // `timespec64_valid`: tv_nsec must be < NSEC_PER_SEC, tv_sec >= 0.
        for bad in [
            [0i64, 1_000_000_000, 1, 0], // it_interval.tv_nsec too large
            [0, 0, 1, -1],               // it_value.tv_nsec negative
            [0, 0, -1, 0],               // it_value.tv_sec negative
        ] {
            if call(
                Syscall::TimerSettime.raw(),
                a3(live, 0, bad.as_ptr() as u64, 0),
            ) != Some(EINVAL)
            {
                return Err("timer_settime with an invalid timespec should be -EINVAL");
            }
        }
        // A timerid that no longer names a timer.
        if call(
            Syscall::TimerSettime.raw(),
            a3(stale, 0, new.as_ptr() as u64, 0),
        ) != Some(EINVAL)
        {
            return Err("timer_settime on a deleted timer should be -EINVAL");
        }
        // `lock_timer`: `if ((unsigned long long)timer_id > INT_MAX) return NULL;`
        if call(
            Syscall::TimerSettime.raw(),
            a3(0x8000_0000, 0, new.as_ptr() as u64, 0),
        ) != Some(EINVAL)
        {
            return Err("timer_settime with a timerid > INT_MAX should be -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_settime_neg);

/// `sys_timer_settime` reports a failed `put_itimerspec64` as EFAULT
/// *after* the timer has been armed — the arm is not rolled back. The old
/// handler swallowed the error and returned 0, which left the caller
/// reading its own uninitialised buffer as the previous setting.
fn smoke_abi_time_timer_settime_faulting_old_efault() -> TestResult {
    with_setup(|| {
        let id = make_timer()?;
        let new: [i64; 4] = [0, 0, 100, 0];
        if call(
            Syscall::TimerSettime.raw(),
            a3(id, 0, new.as_ptr() as u64, FAULTING),
        ) != Some(EFAULT)
        {
            return Err("timer_settime with a faulting old-value buffer should be -EFAULT");
        }
        // ... and the timer really is armed despite the EFAULT.
        let mut cur = [0i64; 4];
        if call(Syscall::TimerGettime.raw(), a1(id, cur.as_mut_ptr() as u64)) != Some(0) {
            return Err("timer_gettime after the EFAULT should still work");
        }
        if cur[2] == 0 && cur[3] == 0 {
            return Err("timer_settime must arm the timer even when the old-value copy faults");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timer_settime_faulting_old_efault
);

// ── timer_gettime(timerid, cur) ───────────────────────────────────────

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

/// `sys_timer_gettime` runs `do_timer_gettime` (EINVAL on a lookup miss)
/// FIRST and only copies out on success — so a stale timerid beats an
/// unwritable buffer, the opposite of `timer_create`'s ordering.
fn smoke_abi_time_timer_gettime_neg() -> TestResult {
    with_setup(|| {
        let live = make_timer()?;
        let stale = stale_timer()?;
        // Never created, deleted, and past INT_MAX — all -EINVAL.
        for id in [0xdead, stale, 0x8000_0000] {
            if call(Syscall::TimerGettime.raw(), a1(id, 0)) != Some(EINVAL) {
                return Err("timer_gettime on an unknown id should be -EINVAL, even with NULL out");
            }
        }
        // A live timer with an unwritable buffer is the EFAULT case.
        for out in [0, FAULTING] {
            if call(Syscall::TimerGettime.raw(), a1(live, out)) != Some(EFAULT) {
                return Err("timer_gettime(live, unwritable out) should be -EFAULT");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_gettime_neg);

// ── timer_delete(timerid) ─────────────────────────────────────────────

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

/// `sys_timer_delete`'s only failure is `scoped_timer_get_or_fail` =
/// -EINVAL. Reaching it by racing a sibling's delete is normal, and as
/// EPERM the caller could not tell "already gone" from "the sandbox took
/// my timers".
fn smoke_abi_time_timer_delete_neg() -> TestResult {
    with_setup(|| {
        let id = make_timer()?;
        if call(Syscall::TimerDelete.raw(), a0(id)) != Some(0) {
            return Err("timer_delete setup failed");
        }
        // Double delete, never-created, and past INT_MAX.
        for bad in [id, 0xdead, 0x8000_0000] {
            if call(Syscall::TimerDelete.raw(), a0(bad)) != Some(EINVAL) {
                return Err("timer_delete on an unknown id should be -EINVAL");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timer_delete_neg);

// ── setitimer(which, new, old) ────────────────────────────────────────

/// Positive paths, including the two Linux accepts that NARF used to
/// reject: a NULL `value` (the documented "misfeature" that means
/// disarm) and a `which` whose upper 32 register bits are garbage.
fn smoke_abi_time_setitimer_pos() -> TestResult {
    with_setup(|| {
        // ITIMER_REAL (0); itimerval = { interval{0,0}, value{0,0} } (disarm).
        let new: [i64; 4] = [0, 0, 0, 0];
        let mut old = [0i64; 4];
        for which in [0, 1, 2] {
            if call(Syscall::Setitimer.raw(), a2(which, new.as_ptr() as u64, 0)) != Some(0) {
                return Err("setitimer(<valid which>, valid, NULL) should return 0");
            }
        }
        if call(
            Syscall::Setitimer.raw(),
            a2(0, new.as_ptr() as u64, old.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("setitimer with an old-value buffer should return 0");
        }
        // `int which`: the upper half of the register is not part of it.
        if call(
            Syscall::Setitimer.raw(),
            a2(1u64 << 32, new.as_ptr() as u64, 0),
        ) != Some(0)
        {
            return Err("setitimer must truncate `which` to 32 bits");
        }
        // `if (value) {...} else { memset(&set_buffer, 0, ...); }` — a NULL
        // new value is ACCEPTED and disarms. Rejecting it left the
        // caller's timer armed while it believed it had cleared it.
        if call(Syscall::Setitimer.raw(), a2(0, 0, old.as_mut_ptr() as u64)) != Some(0) {
            return Err("setitimer(_, NULL, old) is accepted by Linux and must return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_setitimer_pos);

/// `do_setitimer`'s `switch (which) { ... default: return -EINVAL; }`,
/// and `get_itimerval`'s EFAULT/EINVAL — which run FIRST, so a faulting
/// value beats a bad `which`.
fn smoke_abi_time_setitimer_neg() -> TestResult {
    with_setup(|| {
        let new: [i64; 4] = [0, 0, 0, 0];
        // which=5 is past ITIMER_PROF(2).
        if call(Syscall::Setitimer.raw(), a2(5, new.as_ptr() as u64, 0)) != Some(EINVAL) {
            return Err("setitimer on an invalid `which` should be -EINVAL");
        }
        // Negative `which` sign-extends to a huge u64 but is still just
        // an out-of-range int.
        if call(
            Syscall::Setitimer.raw(),
            a2(u64::MAX, new.as_ptr() as u64, 0),
        ) != Some(EINVAL)
        {
            return Err("setitimer(-1, _, _) should be -EINVAL");
        }
        // ORDER: the value is parsed before `which` is looked at.
        if call(Syscall::Setitimer.raw(), a2(5, FAULTING, 0)) != Some(EFAULT) {
            return Err("setitimer(bad which, faulting value, _) should be -EFAULT");
        }
        // `timeval_valid`: tv_usec must be < USEC_PER_SEC, tv_sec >= 0.
        for bad in [
            [0i64, 1_000_000, 0, 0], // it_interval.tv_usec too large
            [0, 0, 0, -1],           // it_value.tv_usec negative
            [0, 0, -1, 0],           // it_value.tv_sec negative
        ] {
            if call(Syscall::Setitimer.raw(), a2(0, bad.as_ptr() as u64, 0)) != Some(EINVAL) {
                return Err("setitimer with an invalid timeval should be -EINVAL");
            }
        }
        // `if (put_itimerval(ovalue, &get_buffer)) return -EFAULT;` — the
        // new value is still installed, only the report is lost.
        if call(
            Syscall::Setitimer.raw(),
            a2(0, new.as_ptr() as u64, FAULTING),
        ) != Some(EFAULT)
        {
            return Err("setitimer with a faulting old-value buffer should be -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_setitimer_neg);

// ── getitimer(which, cur) ─────────────────────────────────────────────

fn smoke_abi_time_getitimer_pos() -> TestResult {
    with_setup(|| {
        let mut cur = [0i64; 4];
        let out = cur.as_mut_ptr() as u64;
        for which in [0, 1, 2] {
            if call(Syscall::Getitimer.raw(), a1(which, out)) != Some(0) {
                return Err("getitimer(<valid which>, buf) should return 0");
            }
        }
        // `int which` — truncate, do not read the whole register.
        if call(Syscall::Getitimer.raw(), a1(1u64 << 32, out)) != Some(0) {
            return Err("getitimer must truncate `which` to 32 bits");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_getitimer_pos);

/// `sys_getitimer` runs `do_getitimer` (EINVAL) before `put_itimerval`
/// (EFAULT), so a bad `which` wins over an unwritable buffer.
fn smoke_abi_time_getitimer_neg() -> TestResult {
    with_setup(|| {
        // Bad `which` + NULL out → the `which` check wins.
        if call(Syscall::Getitimer.raw(), a1(99, 0)) != Some(EINVAL) {
            return Err("getitimer(bad which, NULL) should be -EINVAL");
        }
        if call(Syscall::Getitimer.raw(), a1(u64::MAX, 0)) != Some(EINVAL) {
            return Err("getitimer(-1, NULL) should be -EINVAL");
        }
        // Valid `which` + unwritable buffer → EFAULT.
        for out in [0, FAULTING] {
            if call(Syscall::Getitimer.raw(), a1(0, out)) != Some(EFAULT) {
                return Err("getitimer(ITIMER_REAL, unwritable out) should be -EFAULT");
            }
        }
        Ok(())
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

/// `SYSCALL_DEFINE1(alarm, unsigned int, seconds)` — the argument is 32
/// bits. Reading the whole register turned `alarm(1 << 32)` into a
/// ~136-year timer where Linux truncates to 0 and CANCELS the alarm; a
/// watchdog handed a computed 64-bit value would simply never fire.
fn smoke_abi_time_alarm_truncates_to_u32() -> TestResult {
    with_setup(|| {
        if call(Syscall::Alarm.raw(), a0(100)).is_none() {
            return Err("alarm(100) should succeed");
        }
        // 1<<32 truncates to 0 seconds → this is a cancel, and it reports
        // the ~100 s still on the previous alarm.
        match call(Syscall::Alarm.raw(), a0(1u64 << 32)) {
            Some(v) if v >= 1 => {}
            _ => return Err("alarm(1<<32) should behave as alarm(0) and report the remainder"),
        }
        // Truly cancelled: nothing left to report.
        match call(Syscall::Alarm.raw(), a0(0)) {
            Some(0) => Ok(()),
            _ => Err("alarm(1<<32) must have disarmed the alarm"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_alarm_truncates_to_u32);

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

// The `timerfd_settime` error ladder — fs/timerfd.c. The SYSCALL wrapper
// reads `utmr` FIRST, so -EFAULT beats every other error; only then does
// do_timerfd_settime validate flags/value, and only then the descriptor:
//
//   get_itimerspec64(&new, utmr)                    -> -EFAULT
//   (flags & ~TFD_SETTIME_FLAGS) || !valid(new)     -> -EINVAL
//   fd_empty(f)                                     -> -EBADF
//   f_op != &timerfd_fops                           -> -EINVAL
//   otmr && put_itimerspec64(&old, otmr)            -> -EFAULT

fn smoke_abi_time_timerfd_settime_neg() -> TestResult {
    with_setup(|| {
        let fd = make_timerfd()?;
        // NULL `utmr` faults in get_itimerspec64 — Linux has no null check
        // here, the copy simply fails. -1 reached the caller as EPERM.
        match call(Syscall::TimerfdSettime.raw(), a3(fd, 0, 0, 0)) {
            Some(-14) => Ok(()),
            Some(-1) => Err("timerfd_settime(NULL new) still returns the -1/EPERM sentinel"),
            _ => Err("timerfd_settime(_, _, NULL, _) should return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timerfd_settime_neg);

fn smoke_abi_time_timerfd_settime_efault_beats_ebadf() -> TestResult {
    with_setup(|| {
        // `get_itimerspec64` runs in the SYSCALL wrapper, before
        // do_timerfd_settime ever sees `ufd`. So a bad pointer AND a bad
        // descriptor together is -EFAULT, not -EBADF.
        match call(Syscall::TimerfdSettime.raw(), a3(4242, 0, 0, 0)) {
            Some(-14) => Ok(()),
            Some(-9) => Err("timerfd_settime checked the fd before reading utmr (wrong order)"),
            _ => Err("timerfd_settime(bad fd, NULL new) should return -EFAULT"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timerfd_settime_efault_beats_ebadf
);

fn smoke_abi_time_timerfd_settime_bad_flags_einval() -> TestResult {
    with_setup(|| {
        // `if ((flags & ~TFD_SETTIME_FLAGS) || ...) return -EINVAL;` with
        // TFD_SETTIME_FLAGS = TFD_TIMER_ABSTIME|TFD_TIMER_CANCEL_ON_SET.
        // The old handler read bit 0 and DISCARDED the rest, so an
        // unsupported flag armed a timer while the caller believed it had
        // semantics it never got — an accepted-and-ignored argument, which
        // is worse than a wrong errno because nothing reports it.
        let fd = make_timerfd()?;
        let new: [i64; 4] = [0, 0, 1, 0];
        match call(
            Syscall::TimerfdSettime.raw(),
            a3(fd, 0x4, new.as_ptr() as u64, 0),
        ) {
            Some(-22) => Ok(()),
            Some(0) => Err("timerfd_settime accepted and ignored an unsupported flag"),
            _ => Err("timerfd_settime with an unknown flag should return -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timerfd_settime_bad_flags_einval
);

fn smoke_abi_time_timerfd_settime_abstime_accepted() -> TestResult {
    with_setup(|| {
        // Both defined flags must still be accepted: TFD_TIMER_ABSTIME (1)
        // and TFD_TIMER_CANCEL_ON_SET (2). Pins that the new mask rejects
        // only what Linux rejects.
        let new: [i64; 4] = [0, 0, 1, 0];
        for flags in [0u64, 1, 2, 3] {
            let fd = make_timerfd()?;
            match call(
                Syscall::TimerfdSettime.raw(),
                a3(fd, flags, new.as_ptr() as u64, 0),
            ) {
                Some(0) => {}
                _ => return Err("timerfd_settime rejected a flag combination Linux accepts"),
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timerfd_settime_abstime_accepted
);

fn smoke_abi_time_timerfd_settime_bad_itimerspec_einval() -> TestResult {
    with_setup(|| {
        // `!itimerspec64_valid(new)` -> -EINVAL. `timespec64_valid`
        // (include/linux/time64.h) rejects tv_sec < 0 and, via a cast to
        // unsigned long, ANY tv_nsec outside [0, NSEC_PER_SEC).
        //
        // This was unvalidated, and the consequence was not merely a missing
        // errno: a negative tv_sec went through
        // `(value_sec as u64).saturating_mul(1_000_000_000)`, reinterpreting
        // the sign bit as an enormous positive delay — a timer that silently
        // never fires instead of an error at the call site.
        let cases: [([i64; 4], &str); 4] = [
            ([0, 0, -1, 0], "negative value tv_sec"),
            ([0, 0, 0, 1_000_000_000], "value tv_nsec >= NSEC_PER_SEC"),
            ([0, 0, 0, -1], "negative value tv_nsec"),
            ([-1, 0, 1, 0], "negative interval tv_sec"),
        ];
        for (new, what) in cases {
            let fd = make_timerfd()?;
            match call(
                Syscall::TimerfdSettime.raw(),
                a3(fd, 0, new.as_ptr() as u64, 0),
            ) {
                Some(-22) => {}
                Some(0) => {
                    let _ = what;
                    return Err("timerfd_settime armed a timer from an invalid itimerspec");
                }
                _ => return Err("timerfd_settime with an invalid itimerspec should be -EINVAL"),
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timerfd_settime_bad_itimerspec_einval
);

fn smoke_abi_time_timerfd_settime_bad_fd_ebadf() -> TestResult {
    with_setup(|| {
        // Past the EFAULT and EINVAL guards: `if (fd_empty(f)) return -EBADF;`
        let new: [i64; 4] = [0, 0, 1, 0];
        match call(
            Syscall::TimerfdSettime.raw(),
            a3(4242, 0, new.as_ptr() as u64, 0),
        ) {
            Some(-9) => Ok(()),
            Some(-1) => Err("timerfd_settime(bad fd) still returns the -1/EPERM sentinel"),
            _ => Err("timerfd_settime on an unopened fd should return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timerfd_settime_bad_fd_ebadf);

fn smoke_abi_time_timerfd_settime_not_a_timerfd_einval() -> TestResult {
    with_setup(|| {
        // `if (fd_file(f)->f_op != &timerfd_fops) return -EINVAL;` — a live
        // descriptor of the wrong type is EINVAL, distinct from the EBADF a
        // never-opened one gets. Collapsing both into one -1 hid a plain
        // programming error behind a permissions failure.
        let ok = match call(Syscall::Eventfd.raw(), a1(0, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("eventfd2 setup failed"),
        };
        let new: [i64; 4] = [0, 0, 1, 0];
        match call(
            Syscall::TimerfdSettime.raw(),
            a3(ok, 0, new.as_ptr() as u64, 0),
        ) {
            Some(-22) => Ok(()),
            Some(-9) => Err("timerfd_settime reported EBADF for a live non-timerfd descriptor"),
            _ => Err("timerfd_settime on a non-timerfd should return -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timerfd_settime_not_a_timerfd_einval
);

fn smoke_abi_time_timerfd_settime_old_fault_still_arms() -> TestResult {
    with_setup(|| {
        // `old` is snapshotted inside do_timerfd_settime BEFORE the re-arm,
        // but the `otmr` copy-out happens in the SYSCALL wrapper AFTER
        // do_timerfd_settime returns — so a faulting `otmr` reports -EFAULT
        // with the new timer ALREADY ARMED. Writing `otmr` before arming
        // would make that EFAULT mean "nothing changed", and a caller that
        // fixed its pointer and retried would re-arm an already-running
        // timer.
        let fd = make_timerfd()?;
        let new: [i64; 4] = [0, 0, 500, 0];
        match call(
            Syscall::TimerfdSettime.raw(),
            a3(fd, 0, new.as_ptr() as u64, BAD_PTR),
        ) {
            Some(-14) => {}
            _ => return Err("timerfd_settime with an unmapped otmr should return -EFAULT"),
        }
        // The timer must nevertheless be armed: gettime reports a non-zero
        // remaining value.
        let mut cur = [0i64; 4];
        match call(
            Syscall::TimerfdGettime.raw(),
            a1(fd, cur.as_mut_ptr() as u64),
        ) {
            Some(0) if cur[2] != 0 || cur[3] != 0 => Ok(()),
            Some(0) => Err("timerfd_settime rolled back the arm when otmr faulted"),
            _ => Err("timerfd_gettime failed after a faulting otmr"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timerfd_settime_old_fault_still_arms
);

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

// The `timerfd_gettime` ladder — fs/timerfd.c. Note there is NO null check
// on `otmr`: the descriptor is validated first, and a bad output pointer
// simply fails in put_itimerspec64.
//
//   fd_empty(f)                             -> -EBADF
//   f_op != &timerfd_fops                   -> -EINVAL
//   put_itimerspec64(&kotmr, otmr)          -> -EFAULT

fn smoke_abi_time_timerfd_gettime_neg() -> TestResult {
    with_setup(|| {
        let mut cur = [0i64; 4];
        // fd 4242 was never opened: `if (fd_empty(f)) return -EBADF;`
        match call(
            Syscall::TimerfdGettime.raw(),
            a1(4242, cur.as_mut_ptr() as u64),
        ) {
            Some(-9) => Ok(()),
            Some(-1) => Err("timerfd_gettime(bad fd) still returns the -1/EPERM sentinel"),
            _ => Err("timerfd_gettime on a bad fd should return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_timerfd_gettime_neg);

fn smoke_abi_time_timerfd_gettime_not_a_timerfd_einval() -> TestResult {
    with_setup(|| {
        // A live descriptor of the wrong type: -EINVAL, not -EBADF.
        let ok = match call(Syscall::Eventfd.raw(), a1(0, 0)) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("eventfd2 setup failed"),
        };
        let mut cur = [0i64; 4];
        match call(
            Syscall::TimerfdGettime.raw(),
            a1(ok, cur.as_mut_ptr() as u64),
        ) {
            Some(-22) => Ok(()),
            Some(-9) => Err("timerfd_gettime reported EBADF for a live non-timerfd descriptor"),
            _ => Err("timerfd_gettime on a non-timerfd should return -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timerfd_gettime_not_a_timerfd_einval
);

fn smoke_abi_time_timerfd_gettime_null_out_efault() -> TestResult {
    with_setup(|| {
        // Linux never null-checks `otmr` — it reaches put_itimerspec64 and
        // faults, which is -EFAULT. The old handler checked `out_ptr == 0`
        // first and returned -1 (EPERM).
        let fd = make_timerfd()?;
        match call(Syscall::TimerfdGettime.raw(), a1(fd, 0)) {
            Some(-14) => Ok(()),
            Some(-1) => Err("timerfd_gettime(NULL out) still returns the -1/EPERM sentinel"),
            _ => Err("timerfd_gettime with a NULL out pointer should return -EFAULT"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timerfd_gettime_null_out_efault
);

fn smoke_abi_time_timerfd_gettime_ebadf_beats_efault() -> TestResult {
    with_setup(|| {
        // Ordering: the descriptor is validated BEFORE the output pointer is
        // touched, so a bad fd and a null out together is -EBADF. The old
        // handler checked the pointer first and got this backwards.
        match call(Syscall::TimerfdGettime.raw(), a1(4242, 0)) {
            Some(-9) => Ok(()),
            Some(-14) => Err("timerfd_gettime checked the out pointer before the fd (wrong order)"),
            _ => Err("timerfd_gettime(bad fd, NULL out) should return -EBADF"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_time_timerfd_gettime_ebadf_beats_efault
);

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

fn smoke_abi_time_gettimeofday_efault() -> TestResult {
    with_setup(|| {
        // A non-NULL but faulting tv → -EFAULT (put_user), matching Linux.
        // (NULL is the allowed no-op above; only a bad non-NULL ptr faults.)
        if call(Syscall::Gettimeofday.raw(), a1(u64::MAX, 0)) != Some(EFAULT) {
            return Err("gettimeofday(faulting tv) should return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_gettimeofday_efault);

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

fn smoke_abi_time_settimeofday_neg() -> TestResult {
    with_setup(|| {
        // A non-NULL but faulting tv → -EFAULT (copy_from_user).
        if call(Syscall::Settimeofday.raw(), a1(u64::MAX, 0)) != Some(EFAULT) {
            return Err("settimeofday(faulting tv) should return -EFAULT");
        }
        // tv_usec out of range ([0, 1e6)) → -EINVAL (timeval_valid).
        let bad: [i64; 2] = [1, 1_000_000];
        if call(Syscall::Settimeofday.raw(), a1(bad.as_ptr() as u64, 0)) != Some(EINVAL) {
            return Err("settimeofday with tv_usec >= 1e6 should return -EINVAL");
        }
        // tv_sec < 0 → -EINVAL.
        let neg: [i64; 2] = [-1, 0];
        if call(Syscall::Settimeofday.raw(), a1(neg.as_ptr() as u64, 0)) != Some(EINVAL) {
            return Err("settimeofday with tv_sec < 0 should return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_time_settimeofday_neg);

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
