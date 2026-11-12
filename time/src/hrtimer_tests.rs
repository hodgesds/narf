//! Smokes for the per-CPU hrtimer bases (`time/hrtimer`).
//!
//! They run against the live per-CPU bases of the test CPU, alongside the
//! system's own timers, so they assert only on timers they own.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::hrtimer::{
    self, hrtimer_cancel, hrtimer_start_on, hrtimer_start_range_ns, ClockId, HrTimer, HrtimerMode,
    HrtimerRestart, SleepHandle,
};

/// A timer with a fire counter (`container_of` via `repr(C)`).
#[repr(C)]
struct Counted {
    timer: HrTimer,
    fired: AtomicUsize,
    /// Order stamp of the last fire.
    order: AtomicU64,
    /// Remaining restarts for the periodic test.
    restarts: AtomicUsize,
    interval: u64,
}

static ORDER: AtomicU64 = AtomicU64::new(0);

fn counted_fn(t: &HrTimer) -> HrtimerRestart {
    // SAFETY: only `Counted` timers use this callback; `timer` is the first
    // field of the repr(C) struct.
    let c = unsafe { &*(t as *const HrTimer as *const Counted) };
    c.fired.fetch_add(1, Ordering::AcqRel);
    c.order
        .store(ORDER.fetch_add(1, Ordering::AcqRel), Ordering::Release);
    if c.restarts.load(Ordering::Acquire) > 0 {
        c.restarts.fetch_sub(1, Ordering::AcqRel);
        t.forward(crate::monotonic_ns(), c.interval);
        return HrtimerRestart::Restart;
    }
    HrtimerRestart::NoRestart
}

fn counted(mode: HrtimerMode) -> Box<Counted> {
    Box::new(Counted {
        timer: HrTimer::new(counted_fn, ClockId::Monotonic, mode),
        fired: AtomicUsize::new(0),
        order: AtomicU64::new(0),
        restarts: AtomicUsize::new(0),
        interval: 0,
    })
}

fn me() -> usize {
    narf_lib::percpu::current_cpu()
}

/// Expire this CPU's due timers until `done` or a 200 ms budget passes.
fn expire_until(mut done: impl FnMut() -> bool) -> bool {
    let end = crate::monotonic_ns() + 200_000_000;
    while crate::monotonic_ns() < end {
        hrtimer::hrtimer_run_softirq();
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    done()
}

/// Thousands of timers in one clock base, many with the same expiry: no
/// capacity limit, each fires exactly once, in expiry order (FIFO on ties).
fn smoke_hrtimer_many_timers_one_base_fire_once_in_order() -> TestResult {
    const N: usize = 4096;
    let now = crate::monotonic_ns();
    let timers: Vec<Box<Counted>> = (0..N).map(|_| counted(HrtimerMode::ABS_HARD)).collect();
    narf_lib::sync::without_interrupts(|| {
        for (i, t) in timers.iter().enumerate() {
            // 64 distinct expiries, all just in the past, in reverse order.
            let exp = now - 1_000 - (i % 64) as u64;
            // SAFETY: the Box keeps the timer in place; cancelled below.
            unsafe { hrtimer_start_range_ns(&t.timer, exp, 0, HrtimerMode::ABS) };
        }
    });
    if hrtimer::__test_validate(me()).is_err() {
        return TestResult::Fail("timer queue invariants broken after bulk enqueue");
    }
    let ok = expire_until(|| timers.iter().all(|t| t.fired.load(Ordering::Acquire) >= 1));
    for t in &timers {
        hrtimer_cancel(&t.timer);
    }
    if !ok || timers.iter().any(|t| t.fired.load(Ordering::Acquire) != 1) {
        return TestResult::Fail("a queued timer did not fire exactly once");
    }
    // Earlier expiry fires first; equal expiry fires in enqueue order.
    let mut by_exp: Vec<(u64, usize, u64)> = timers
        .iter()
        .enumerate()
        .map(|(i, t)| {
            (
                now - 1_000 - (i % 64) as u64,
                i,
                t.order.load(Ordering::Acquire),
            )
        })
        .collect();
    by_exp.sort_unstable_by_key(|e| (e.0, e.1));
    if by_exp.windows(2).any(|w| w[0].2 > w[1].2) {
        return TestResult::Fail("timers fired out of expiry/enqueue order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "time/hrtimer",
    smoke_hrtimer_many_timers_one_base_fire_once_in_order
);

/// Cancel unlinks a pending timer (it never fires), restart moves the
/// expiry, and cancel of a fired timer is a no-op.
fn smoke_hrtimer_cancel_and_restart() -> TestResult {
    let a = counted(HrtimerMode::ABS_HARD);
    let b = counted(HrtimerMode::ABS_HARD);
    let now = crate::monotonic_ns();
    // SAFETY: Boxes stay put; cancelled before drop.
    unsafe {
        hrtimer_start_range_ns(&a.timer, now + 10_000_000_000, 0, HrtimerMode::ABS);
        hrtimer_start_range_ns(&b.timer, now + 10_000_000_000, 0, HrtimerMode::ABS);
    }
    if !a.timer.is_queued() || hrtimer::hrtimer_try_to_cancel(&a.timer) != 1 || a.timer.is_queued()
    {
        hrtimer_cancel(&b.timer);
        return TestResult::Fail("cancel did not unlink a pending timer");
    }
    // Restart b into the past: it fires; a never does.
    // SAFETY: as above.
    unsafe { hrtimer_start_range_ns(&b.timer, 0, 0, HrtimerMode::REL) };
    let fired = expire_until(|| b.fired.load(Ordering::Acquire) == 1);
    let cancel_after = hrtimer::hrtimer_try_to_cancel(&b.timer);
    hrtimer_cancel(&a.timer);
    if !fired || a.fired.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("restart or cancel changed which timer fired");
    }
    if cancel_after != 0 {
        return TestResult::Fail("cancel of a fired timer reported it pending");
    }
    if hrtimer::__test_validate(me()).is_err() {
        return TestResult::Fail("timer queue invariants broken");
    }
    TestResult::Pass
}
kernel_test_in!("time/hrtimer", smoke_hrtimer_cancel_and_restart);

/// A callback that forwards and returns `Restart` is re-queued and fires
/// again (`hrtimer_forward` periodic shape).
fn smoke_hrtimer_restart_from_callback() -> TestResult {
    let mut t = counted(HrtimerMode::ABS_HARD);
    t.interval = 1_000_000;
    t.restarts.store(3, Ordering::Release);
    // SAFETY: the Box stays put; cancelled below.
    unsafe { hrtimer_start_range_ns(&t.timer, 0, 0, HrtimerMode::REL) };
    let ok = expire_until(|| t.fired.load(Ordering::Acquire) == 4);
    hrtimer_cancel(&t.timer);
    if !ok {
        return TestResult::Fail("a restarting timer did not fire four times");
    }
    TestResult::Pass
}
kernel_test_in!("time/hrtimer", smoke_hrtimer_restart_from_callback);

/// The REALTIME base is ordered by realtime expiry and converted through the
/// wall offset; a soft-mode timer expires from the softirq-equivalent.
fn smoke_hrtimer_realtime_and_soft_bases() -> TestResult {
    let rt = Box::new(Counted {
        timer: HrTimer::new(counted_fn, ClockId::Realtime, HrtimerMode::ABS_SOFT),
        fired: AtomicUsize::new(0),
        order: AtomicU64::new(0),
        restarts: AtomicUsize::new(0),
        interval: 0,
    });
    let real_now = hrtimer::clock_now(ClockId::Realtime);
    // SAFETY: the Box stays put; cancelled below.
    unsafe { hrtimer_start_range_ns(&rt.timer, real_now + 2_000_000, 0, HrtimerMode::ABS) };
    let early = rt.fired.load(Ordering::Acquire);
    let ok = expire_until(|| rt.fired.load(Ordering::Acquire) == 1);
    hrtimer_cancel(&rt.timer);
    if early != 0 {
        return TestResult::Fail("a REALTIME timer fired before its expiry");
    }
    if !ok {
        return TestResult::Fail("a soft REALTIME timer never expired");
    }
    TestResult::Pass
}
kernel_test_in!("time/hrtimer", smoke_hrtimer_realtime_and_soft_bases);

struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

/// A sleeper wakes its waker once; refreshing after expiry reports false so
/// the waiter re-arms; re-arming reuses the sleeper.
fn smoke_hrtimer_sleeper_wakes_and_rearms() -> TestResult {
    let c = Arc::new(CountWake(AtomicUsize::new(0)));
    let w: core::task::Waker = c.clone().into();
    let h = SleepHandle::arm(crate::monotonic_ns() + 1_000_000, 0, &w);
    if !h.refresh_waker(&w) {
        return TestResult::Fail("refresh of a pending sleeper failed");
    }
    if !expire_until(|| c.0.load(Ordering::Acquire) == 1) || !h.fired() {
        return TestResult::Fail("sleeper did not wake its waker");
    }
    if h.refresh_waker(&w) {
        return TestResult::Fail("refresh of a fired sleeper reported it pending");
    }
    h.start(crate::monotonic_ns(), 0, HrtimerMode::ABS, &w);
    if !expire_until(|| c.0.load(Ordering::Acquire) == 2) {
        return TestResult::Fail("re-armed sleeper did not wake");
    }
    drop(h);
    if Arc::strong_count(&c) != 2 {
        return TestResult::Fail("dropping the sleeper leaked or over-released its waker");
    }
    TestResult::Pass
}
kernel_test_in!("time/hrtimer", smoke_hrtimer_sleeper_wakes_and_rearms);

/// A CPU going offline hands its timers to the caller's base
/// (`hrtimers_cpu_dying`); they then fire there. Uses an index that has
/// never been online as the dying CPU.
fn smoke_hrtimer_offline_moves_timers() -> TestResult {
    let ever = narf_lib::smp::ever_online_bitmap();
    let Some(dead) = (1..narf_lib::percpu::MAX_CPUS)
        .rev()
        .find(|c| ever & (1u64 << c) == 0)
    else {
        return TestResult::Skip("every CPU index has been online");
    };
    hrtimer::hrtimers_prepare_cpu(dead);
    let timers: Vec<Box<Counted>> = (0..64).map(|_| counted(HrtimerMode::ABS_HARD)).collect();
    let soon = crate::monotonic_ns() + 1_000_000;
    for t in &timers {
        // SAFETY: Boxes stay put; cancelled below.
        unsafe { hrtimer_start_on(&t.timer, dead, soon, 0, HrtimerMode::ABS) };
    }
    if hrtimer::nr_queued_on(dead) != 64 {
        for t in &timers {
            hrtimer_cancel(&t.timer);
        }
        return TestResult::Fail("timers did not queue on the named CPU's base");
    }
    let moved = hrtimer::hrtimers_cpu_dying(dead);
    let left = hrtimer::nr_queued_on(dead);
    let ok = expire_until(|| timers.iter().all(|t| t.fired.load(Ordering::Acquire) == 1));
    for t in &timers {
        hrtimer_cancel(&t.timer);
    }
    if moved != 64 || left != 0 {
        return TestResult::Fail("offline did not move every timer off the dying base");
    }
    if !ok {
        return TestResult::Fail("a migrated timer did not fire on its new base");
    }
    TestResult::Pass
}
kernel_test_in!("time/hrtimer", smoke_hrtimer_offline_moves_timers);

/// `clock_was_set`: stepping the wall clock forward past a pending
/// CLOCK_REALTIME timer's expiry makes it due at once (its base offset moved),
/// while a MONOTONIC timer with the same distance stays pending.
fn smoke_hrtimer_clock_was_set_moves_realtime_timers() -> TestResult {
    let rt = Box::new(Counted {
        timer: HrTimer::new(counted_fn, ClockId::Realtime, HrtimerMode::ABS_HARD),
        fired: AtomicUsize::new(0),
        order: AtomicU64::new(0),
        restarts: AtomicUsize::new(0),
        interval: 0,
    });
    let mono = counted(HrtimerMode::ABS_HARD);
    const AHEAD: u64 = 10_000_000_000;
    let saved = crate::wall_offset_ns();
    // SAFETY: the Boxes stay put; cancelled below.
    unsafe {
        hrtimer_start_range_ns(
            &rt.timer,
            hrtimer::clock_now(ClockId::Realtime) + AHEAD,
            0,
            HrtimerMode::ABS,
        );
        hrtimer_start_range_ns(
            &mono.timer,
            crate::monotonic_ns() + AHEAD,
            0,
            HrtimerMode::ABS,
        );
    }
    // Step the wall clock 20 s forward (settimeofday): this calls
    // `clock_was_set`.
    crate::set_wall_offset_uncapped(saved.saturating_add(2 * AHEAD as i64));
    let fired = expire_until(|| rt.fired.load(Ordering::Acquire) == 1);
    let mono_pending = mono.timer.is_queued() && mono.fired.load(Ordering::Acquire) == 0;
    crate::set_wall_offset_uncapped(saved);
    hrtimer_cancel(&rt.timer);
    hrtimer_cancel(&mono.timer);
    if !fired {
        return TestResult::Fail("a wall-clock step past a REALTIME timer did not expire it");
    }
    if !mono_pending {
        return TestResult::Fail("a wall-clock step moved a MONOTONIC timer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "time/hrtimer",
    smoke_hrtimer_clock_was_set_moves_realtime_timers
);

/// Linux's MONOTONIC/BOOTTIME split across a suspend: while timekeeping is
/// suspended CLOCK_MONOTONIC stands still; on resume the time asleep is
/// injected into CLOCK_BOOTTIME (`offs_boot`) only. A BOOTTIME hrtimer
/// therefore comes due by the time slept, a MONOTONIC one with the same
/// distance does not, and monotonic time continues from where it stopped.
fn smoke_timekeeping_suspend_injects_boottime() -> TestResult {
    const SLEEP_NS: u64 = 20_000_000;
    const AHEAD: u64 = 30_000_000;
    let boot = Box::new(Counted {
        timer: HrTimer::new(counted_fn, ClockId::Boottime, HrtimerMode::ABS_HARD),
        fired: AtomicUsize::new(0),
        order: AtomicU64::new(0),
        restarts: AtomicUsize::new(0),
        interval: 0,
    });
    let mono = counted(HrtimerMode::ABS_HARD);
    let (m0, b0) = (crate::monotonic_ns(), crate::boottime_ns());
    // SAFETY: the Boxes stay put; cancelled below.
    unsafe {
        hrtimer_start_range_ns(&boot.timer, b0 + AHEAD, 0, HrtimerMode::ABS);
        hrtimer_start_range_ns(&mono.timer, m0 + AHEAD, 0, HrtimerMode::ABS);
    }
    crate::timekeeping_suspend();
    let frozen = crate::monotonic_ns();
    let t = crate::raw_cycles();
    while crate::raw_cycles().wrapping_sub(t) < crate::ns_to_cycles(SLEEP_NS) {
        core::hint::spin_loop();
    }
    let still = crate::monotonic_ns();
    let slept = crate::timekeeping_resume();
    let (m1, b1) = (crate::monotonic_ns(), crate::boottime_ns());
    let ok_order = expire_until(|| {
        boot.fired.load(Ordering::Acquire) == 1 && mono.fired.load(Ordering::Acquire) == 1
    }) && boot.order.load(Ordering::Acquire) < mono.order.load(Ordering::Acquire);
    hrtimer_cancel(&boot.timer);
    hrtimer_cancel(&mono.timer);
    if still != frozen {
        return TestResult::Fail("CLOCK_MONOTONIC advanced while timekeeping was suspended");
    }
    if slept < SLEEP_NS {
        return TestResult::Fail("resume injected less than the time asleep");
    }
    if m1.saturating_sub(m0) > 5_000_000 {
        return TestResult::Fail("CLOCK_MONOTONIC counted the time asleep");
    }
    let boot_gain = b1.saturating_sub(b0).saturating_sub(m1.saturating_sub(m0));
    if boot_gain.abs_diff(slept) > 1_000_000 {
        return TestResult::Fail("CLOCK_BOOTTIME did not gain exactly the time asleep");
    }
    if !ok_order {
        return TestResult::Fail("the BOOTTIME timer did not come due before the MONOTONIC one");
    }
    TestResult::Pass
}
kernel_test_in!("time/hrtimer", smoke_timekeeping_suspend_injects_boottime);
