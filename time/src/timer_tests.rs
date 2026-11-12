//! Smokes for the timer wheel (`time/timer`).

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::timer::{
    self, add_timer_on, calc_wheel_index, del_timer, del_timer_sync, jiffies, mod_timer, TimerList,
    LVL_DEPTH, TIMER_DEFERRABLE, TIMER_PINNED,
};

/// A wheel timer with a fire counter and the jiffy it fired at.
#[repr(C)]
struct Counted {
    timer: TimerList,
    fired: AtomicUsize,
    at: AtomicU64,
}

fn counted_fn(t: &TimerList) {
    // SAFETY: only `Counted` uses this callback; `timer` is its first field.
    let c = unsafe { &*(t as *const TimerList as *const Counted) };
    c.at.store(jiffies(), Ordering::Release);
    c.fired.fetch_add(1, Ordering::AcqRel);
}

fn counted(flags: u32) -> Box<Counted> {
    Box::new(Counted {
        timer: TimerList::new(counted_fn, flags),
        fired: AtomicUsize::new(0),
        at: AtomicU64::new(0),
    })
}

/// Run this CPU's timer softirq until `done` or a 2 s budget passes.
fn run_until(mut done: impl FnMut() -> bool) -> bool {
    let end = crate::monotonic_ns() + 2_000_000_000;
    while crate::monotonic_ns() < end {
        timer::run_timer_softirq();
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    done()
}

/// `calc_wheel_index` places every expiry in a bucket that expires no
/// earlier than the timer and at most one level granularity later, at the
/// level Linux picks for its distance.
fn smoke_timer_wheel_index_bounds() -> TestResult {
    let clk = 1_000_000u64;
    let mut delta = 0u64;
    while delta < 1 << 30 {
        let expires = clk + delta;
        let (idx, bucket) = calc_wheel_index(expires, clk);
        let lvl = idx / 64;
        if lvl >= LVL_DEPTH {
            return TestResult::Fail("bucket index past the last level");
        }
        let gran = 1u64 << (3 * lvl);
        if bucket < expires && delta < (63u64 << (3 * (LVL_DEPTH - 1))) {
            return TestResult::Fail("a bucket expires before its timer");
        }
        if bucket > expires + gran {
            return TestResult::Fail("a bucket expires more than one granularity late");
        }
        delta = delta * 2 + 1;
    }
    TestResult::Pass
}
kernel_test_in!("time/timer", smoke_timer_wheel_index_bounds);

/// Many timers across levels: each fires exactly once, never before its
/// expiry; a deleted one never fires; no capacity limit.
fn smoke_timer_wheel_fires_once_not_early() -> TestResult {
    const N: usize = 2048;
    let now = jiffies();
    let timers: Vec<Box<Counted>> = (0..N).map(|_| counted(TIMER_PINNED)).collect();
    for (i, t) in timers.iter().enumerate() {
        // 0..=200 jiffies out: levels 0..2.
        // SAFETY: Boxes stay put; deleted below.
        unsafe { mod_timer(&t.timer, now + (i % 201) as u64) };
    }
    let victim = counted(TIMER_PINNED);
    // SAFETY: as above.
    unsafe { mod_timer(&victim.timer, now + 5) };
    let deleted = del_timer(&victim.timer);
    let ok = run_until(|| timers.iter().all(|t| t.fired.load(Ordering::Acquire) >= 1));
    for t in &timers {
        del_timer_sync(&t.timer);
    }
    if !deleted || victim.fired.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("a deleted timer fired");
    }
    if !ok || timers.iter().any(|t| t.fired.load(Ordering::Acquire) != 1) {
        return TestResult::Fail("a wheel timer did not fire exactly once");
    }
    for (i, t) in timers.iter().enumerate() {
        if t.at.load(Ordering::Acquire) < now + (i % 201) as u64 {
            return TestResult::Fail("a wheel timer fired before its expiry");
        }
    }
    TestResult::Pass
}
kernel_test_in!("time/timer", smoke_timer_wheel_fires_once_not_early);

/// `mod_timer` on a pending timer re-arms it (fires once, at the new time);
/// deferrable timers do not count toward an idle CPU's next event.
fn smoke_timer_wheel_mod_and_deferrable() -> TestResult {
    let t = counted(TIMER_PINNED);
    let now = jiffies();
    // SAFETY: Boxes stay put; deleted below.
    unsafe {
        mod_timer(&t.timer, now + 10_000);
        if !mod_timer(&t.timer, now + 3) {
            del_timer_sync(&t.timer);
            return TestResult::Fail("mod_timer did not report the pending timer");
        }
    }
    let fired = run_until(|| t.fired.load(Ordering::Acquire) == 1);
    del_timer_sync(&t.timer);
    if !fired || t.at.load(Ordering::Acquire) > now + 1_000 {
        return TestResult::Fail("mod_timer did not move a pending timer earlier");
    }
    // A deferrable timer due before anything else on this CPU: it is this
    // CPU's next event while active, and changes nothing while idle.
    let d = counted(TIMER_DEFERRABLE);
    crate::timer_migration::tmigr_cpu_deactivate();
    let idle_without = timer::next_timer_event_ns_local();
    crate::timer_migration::tmigr_cpu_activate();
    let soon = jiffies() + 1;
    // SAFETY: as above.
    unsafe { mod_timer(&d.timer, soon) };
    let active_with = timer::next_timer_event_ns_local();
    crate::timer_migration::tmigr_cpu_deactivate();
    let idle_with = timer::next_timer_event_ns_local();
    crate::timer_migration::tmigr_cpu_activate();
    del_timer_sync(&d.timer);
    if active_with > timer::jiffies_to_ns(soon + 1) {
        return TestResult::Fail("an active CPU's next event ignored a deferrable timer");
    }
    if idle_with != idle_without && idle_with <= timer::jiffies_to_ns(soon + 1) {
        return TestResult::Fail("a deferrable timer would wake an idle CPU");
    }
    TestResult::Pass
}
kernel_test_in!("time/timer", smoke_timer_wheel_mod_and_deferrable);

/// `timers_dead_cpu`: a dead CPU's timers move to this CPU and fire here.
fn smoke_timer_wheel_dead_cpu_moves_timers() -> TestResult {
    let ever = narf_lib::smp::ever_online_bitmap();
    let Some(dead) = (1..narf_lib::percpu::MAX_CPUS)
        .rev()
        .find(|c| ever & (1u64 << c) == 0)
    else {
        return TestResult::Skip("every CPU index has been online");
    };
    timer::timers_prepare_cpu(dead);
    let now = jiffies();
    let timers: Vec<Box<Counted>> = (0..32)
        .map(|i| counted(if i % 2 == 0 { TIMER_PINNED } else { 0 }))
        .collect();
    for t in &timers {
        // SAFETY: Boxes stay put; deleted below.
        unsafe { add_timer_on(&t.timer, now + 2, dead) };
    }
    let moved = timer::timers_dead_cpu(dead);
    let me = narf_lib::percpu::current_cpu() as u32;
    let all_here = timers.iter().all(|t| t.timer.cpu() == Some(me));
    let fired = run_until(|| timers.iter().all(|t| t.fired.load(Ordering::Acquire) == 1));
    for t in &timers {
        del_timer_sync(&t.timer);
    }
    if moved != 32 || !all_here {
        return TestResult::Fail("a dead CPU's timers did not all move here");
    }
    if !fired {
        return TestResult::Fail("a moved timer did not fire");
    }
    TestResult::Pass
}
kernel_test_in!("time/timer", smoke_timer_wheel_dead_cpu_moves_timers);
