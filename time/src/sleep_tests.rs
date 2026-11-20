//! Smokes for the kernel sleep primitives' Linux semantics (`time/sleep`):
//! which timer each sleep arms and with how much slack, that timers whose
//! slack windows overlap expire in one interrupt, that wheel timers in one
//! bucket share its expiry, `round_jiffies`, and the arm-site bookkeeping
//! `/proc/timer_list` prints.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::task::{Context, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::hrtimer::{
    self, hrtimer_cancel, hrtimer_start_range_ns, ClockId, HrTimer, HrtimerMode, HrtimerRestart,
};
use crate::timer::{self, TimerList, TimerRef};

const MS: u64 = 1_000_000;
const US: u64 = 1_000;

/// Every constructor picks Linux's timer and slack (see the table in
/// `lib.rs`): `fsleep` 25 % under 4 ms and the wheel from there,
/// `usleep_range` `max - min`, absolute sleeps the 50 µs task slack,
/// `exact` none, `msleep` / `timeout` / `schedule_timeout` the wheel.
fn smoke_sleep_primitives_use_linux_slack() -> TestResult {
    let checks: [(&str, Option<u64>, Option<u64>); 14] = [
        ("fsleep(5)", crate::fsleep(5).slack_ns(), Some(1_250)),
        (
            "fsleep(1000)",
            crate::fsleep(1_000).slack_ns(),
            Some(250 * US),
        ),
        (
            "fsleep(3999)",
            crate::fsleep(3_999).slack_ns(),
            Some(999_750),
        ),
        ("fsleep(4000)", crate::fsleep(4_000).slack_ns(), None),
        ("sleep_us(20000)", crate::sleep_us(20_000).slack_ns(), None),
        (
            "sleep_ns(100us)",
            crate::sleep_ns(100 * US).slack_ns(),
            Some(25 * US),
        ),
        (
            "sleep(1ms)",
            crate::sleep(core::time::Duration::from_millis(1)).slack_ns(),
            Some(250 * US),
        ),
        (
            "sleep_cycles(10ms)",
            crate::sleep_cycles(crate::ns_to_cycles(10 * MS)).slack_ns(),
            None,
        ),
        (
            "usleep_range(100,200)",
            crate::usleep_range(100, 200).slack_ns(),
            Some(100 * US),
        ),
        (
            "usleep_range(200,100)",
            crate::usleep_range(200, 100).slack_ns(),
            Some(0),
        ),
        (
            "sleep_until",
            crate::sleep_until(crate::Deadline::after_ms(1)).slack_ns(),
            Some(crate::DEFAULT_TIMER_SLACK_NS),
        ),
        (
            "SleepUntil::exact",
            crate::SleepUntil::exact(crate::Deadline::after_ms(1).as_instant()).slack_ns(),
            Some(0),
        ),
        (
            "schedule_hrtimeout_range",
            crate::schedule_hrtimeout_range(crate::Deadline::after_ms(1), 7 * US).slack_ns(),
            Some(7 * US),
        ),
        ("msleep(1)", crate::msleep(1).slack_ns(), None),
    ];
    for (what, got, want) in checks {
        if got != want {
            let _ = what;
            return TestResult::Fail("a sleep primitive picked the wrong timer or slack");
        }
    }
    if crate::msleep(1).wheel_flags() != Some(0)
        || crate::sleep_jiffies(3).wheel_flags() != Some(0)
        || crate::sleep_until_jiffies(timer::jiffies() + 3, timer::TIMER_DEFERRABLE).wheel_flags()
            != Some(timer::TIMER_DEFERRABLE)
    {
        return TestResult::Fail("a wheel sleep lost its TIMER_* flags");
    }
    // `fsleep` rounds a long delay up to whole milliseconds, never down.
    let long = crate::fsleep(4_500);
    if long.deadline() < crate::Deadline::after_us(4_500).as_instant() {
        return TestResult::Fail("fsleep(4500) ends before 4.5 ms");
    }
    TestResult::Pass
}
kernel_test_in!("time/sleep", smoke_sleep_primitives_use_linux_slack);

#[repr(C)]
struct Counted {
    timer: HrTimer,
    fired: AtomicUsize,
}

fn counted_fn(t: &HrTimer) -> HrtimerRestart {
    // SAFETY: only `Counted` timers use this callback; `timer` is the first
    // field of the repr(C) struct.
    let c = unsafe { &*(t as *const HrTimer as *const Counted) };
    c.fired.fetch_add(1, Ordering::AcqRel);
    HrtimerRestart::NoRestart
}

fn counted() -> Box<Counted> {
    Box::new(Counted {
        timer: HrTimer::new(counted_fn, ClockId::Monotonic, HrtimerMode::ABS_HARD),
        fired: AtomicUsize::new(0),
    })
}

fn fired(ts: &[Box<Counted>]) -> usize {
    ts.iter().map(|t| t.fired.load(Ordering::Acquire)).sum()
}

fn spin_until(ns: u64) {
    while crate::monotonic_ns() < ns {
        core::hint::spin_loop();
    }
}

/// Timers whose `[soft, soft + slack]` windows overlap expire in ONE pass
/// of the expiry code — one interrupt — at the earliest hard expiry, which
/// is the point of slack (`hrtimer_set_expires_range_ns`). The same soft
/// expiries with no slack need one pass each.
fn smoke_hrtimer_slack_windows_coalesce_into_one_expiry() -> TestResult {
    const N: usize = 8;
    const SPREAD: u64 = 12_500;
    const SLACK: u64 = 200 * US;
    const EXACT_GAP: u64 = 300 * US;
    let ranged: Vec<Box<Counted>> = (0..N).map(|_| counted()).collect();
    let exact: Vec<Box<Counted>> = (0..N).map(|_| counted()).collect();
    let result = narf_lib::sync::without_interrupts(|| {
        let base = crate::monotonic_ns() + 2 * MS;
        let exact_base = base + 2 * MS;
        for (i, t) in ranged.iter().enumerate() {
            // SAFETY: the Boxes stay put and are cancelled below.
            unsafe {
                hrtimer_start_range_ns(&t.timer, base + i as u64 * SPREAD, SLACK, HrtimerMode::ABS)
            };
        }
        for (i, t) in exact.iter().enumerate() {
            // SAFETY: as above.
            unsafe {
                hrtimer_start_range_ns(
                    &t.timer,
                    exact_base + i as u64 * EXACT_GAP,
                    0,
                    HrtimerMode::ABS,
                )
            };
        }
        // The CPU's next event is the earliest HARD expiry: the first
        // ranged timer's soft expiry plus its slack.
        let next = hrtimer::next_event_ns_of(narf_lib::percpu::current_cpu());
        if next.is_some_and(|n| n > base + SLACK) {
            return Err("next event is later than the earliest hard expiry");
        }
        spin_until(base + SLACK);
        hrtimer::hrtimer_run_softirq();
        if fired(&ranged) != N {
            return Err("overlapping slack windows did not expire in one pass");
        }
        spin_until(exact_base);
        hrtimer::hrtimer_run_softirq();
        if fired(&exact) != 1 {
            return Err("zero-slack timers 300 us apart expired together");
        }
        Ok(())
    });
    for t in ranged.iter().chain(exact.iter()) {
        hrtimer_cancel(&t.timer);
    }
    match result {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "time/sleep",
    smoke_hrtimer_slack_windows_coalesce_into_one_expiry
);

fn noop_timer(_: TimerRef) {}

/// Wheel timers whose expiries fall in one bucket share that bucket's
/// expiry (Linux's wheel granularity: 8 jiffies at level 1), and the
/// `/proc/timer_list` wheel snapshot reports bucket, level and expiry.
fn smoke_wheel_timers_in_one_bucket_share_expiry() -> TestResult {
    const N: usize = 8;
    let timers: Vec<Box<TimerList>> = (0..N)
        .map(|_| Box::new(TimerList::new(noop_timer, timer::TIMER_PINNED)))
        .collect();
    let cpu = narf_lib::percpu::current_cpu();
    let (snap, start) = narf_lib::sync::without_interrupts(|| {
        // A level-1 bucket (64..511 jiffies out) holds 8 jiffies.
        let start = (timer::jiffies() + 200).next_multiple_of(8);
        for (i, t) in timers.iter().enumerate() {
            // SAFETY: the Boxes stay put; deleted below.
            unsafe { timer::mod_timer(t, start + i as u64) };
        }
        let mut snap = Vec::new();
        let _ = timer::snapshot_wheel(cpu, 0, &mut snap);
        (snap, start)
    });
    for t in &timers {
        timer::del_timer_sync(t);
    }
    let ours: Vec<_> = snap
        .iter()
        .filter(|s| {
            timers
                .iter()
                .any(|t| s.addr == &**t as *const TimerList as usize)
        })
        .collect();
    if ours.len() != N {
        return TestResult::Fail("the wheel snapshot missed a pending timer");
    }
    let bucket = ((start >> 3) + 1) << 3;
    if ours
        .iter()
        .any(|s| s.level != 1 || s.bucket_expiry != bucket)
    {
        return TestResult::Fail("timers in one level-1 bucket do not share its expiry");
    }
    if ours
        .iter()
        .any(|s| s.expires < start || s.expires >= start + 8)
    {
        return TestResult::Fail("the snapshot reported a wrong expiry");
    }
    TestResult::Pass
}
kernel_test_in!("time/sleep", smoke_wheel_timers_in_one_bucket_share_expiry);

/// `round_jiffies_common`, case by case against kernel/time/timer.c.
fn smoke_round_jiffies_matches_linux() -> TestResult {
    use crate::timer::round_jiffies_common_at as r;
    let cases: [(u64, u64, bool, u64, u64); 7] = [
        // (j, cpu, force_up, now, expected)
        (1_234, 0, false, 900, 1_000), // < HZ/4 past a second: round down
        (1_234, 0, false, 1_000, 1_234), // rounded value not in the future
        (1_300, 0, false, 900, 2_000), // round up
        (1_234, 0, true, 900, 2_000),  // force_up never rounds down
        (1_300, 2, false, 900, 1_994), // 3 jiffies of skew per CPU
        (2_000, 0, false, 1_500, 2_000), // already whole
        (1_995, 2, false, 1_500, 1_994), // skewed whole second
    ];
    for (j, cpu, up, now, want) in cases {
        if r(j, cpu, up, now) != want {
            return TestResult::Fail("round_jiffies differs from Linux");
        }
    }
    // The relative forms return a delay that ends on the rounded jiffy.
    let d = timer::round_jiffies_up_relative(1_500);
    if d < 1_500 {
        return TestResult::Fail("round_jiffies_up_relative shortened the delay");
    }
    TestResult::Pass
}
kernel_test_in!("time/sleep", smoke_round_jiffies_matches_linux);

struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}

/// A sleep records where it was constructed as its timer's arm site; the
/// hrtimer snapshot reports it with the sleeper's `hrtimer_wakeup`
/// function, its expiry range and its queued state.
fn smoke_sleep_records_arm_site() -> TestResult {
    let waker = Waker::from(Arc::new(Noop));
    let mut cx = Context::from_waker(&waker);
    let mut s = crate::usleep_range(5_000_000, 5_001_000);
    let line = line!() - 1;
    if Pin::new(&mut s).poll(&mut cx).is_ready() {
        return TestResult::Fail("a 5 s sleep completed at once");
    }
    let cpu = narf_lib::percpu::current_cpu();
    let mut found = None;
    for index in 0..hrtimer::HRTIMER_MAX_CLOCK_BASES {
        let mut snap = Vec::new();
        hrtimer::snapshot_base(cpu, index, &mut snap);
        if let Some(t) = snap.into_iter().find(|t| {
            t.site
                .is_some_and(|l| l.file() == file!() && l.line() == line)
        }) {
            found = Some(t);
            break;
        }
    }
    drop(s);
    let Some(t) = found else {
        return TestResult::Fail("the armed sleep is missing from the snapshot");
    };
    if t.state != 1 || t.expires - t.softexpires != 1_000 * US {
        return TestResult::Fail("the snapshot reported a wrong state or range");
    }
    TestResult::Pass
}
kernel_test_in!("time/sleep", smoke_sleep_records_arm_site);
