//! Smokes for the timer migration hierarchy (`time/tmigr`).
//!
//! Each builds a private [`Tmigr`] over CPU indices that never came online,
//! so the kernel's own hierarchy and timers are untouched. Where a remote
//! expiry must run a real wheel timer, the timer sits on such an index's
//! GLOBAL base.

extern crate alloc;

use alloc::boxed::Box;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::timer::{self, TimerList};
use crate::timer_migration::Tmigr;

const NONE: u64 = u64::MAX;

/// `n` CPU indices that have never been online, highest first.
fn dead_cpus<const N: usize>() -> Option<[usize; N]> {
    let ever = narf_lib::smp::ever_online_bitmap();
    let mut out = [0; N];
    let mut it = (1..narf_lib::percpu::MAX_CPUS.min(64))
        .rev()
        .filter(|c| ever & (1u64 << c) == 0);
    for slot in &mut out {
        *slot = it.next()?;
    }
    Some(out)
}

/// Sixteen CPUs, four per last-level cache, eight per node: four level-0
/// groups, two node groups, one fan-in group, one root. CPUs sharing a cache
/// share a group; every CPU is four levels from the root; the invariants
/// hold.
fn smoke_tmigr_groups_follow_topology() -> TestResult {
    let h = Box::new(Tmigr::new());
    for cpu in 0..16 {
        h.cpu_online(cpu, Some(cpu as u64 / 4), Some(cpu as u32 / 8));
    }
    for cpu in 0..16 {
        let same = h.group_id(cpu) == h.group_id(cpu / 4 * 4);
        let other = h.group_id(cpu) != h.group_id((cpu + 4) % 16);
        if !same || !other {
            return TestResult::Fail("level-0 groups do not follow the last-level cache");
        }
        if h.depth(cpu) != 4 {
            return TestResult::Fail("a CPU is not four levels from the root");
        }
        if !h.cpu_active(cpu) {
            return TestResult::Fail("an online CPU is not active");
        }
    }
    // Nine CPUs on one cache: a full group of eight, then a second group.
    let g = Box::new(Tmigr::new());
    for cpu in 0..9 {
        g.cpu_online(cpu, Some(7), Some(0));
    }
    if g.group_id(0) != g.group_id(7) || g.group_id(0) == g.group_id(8) {
        return TestResult::Fail("a level-0 group took more than eight CPUs");
    }
    if h.__validate().is_err() || g.__validate().is_err() {
        return TestResult::Fail("hierarchy invariants broken");
    }
    TestResult::Pass
}
kernel_test_in!("time/tmigr", smoke_tmigr_groups_follow_topology);

/// Going idle hands the migrator role on inside a group; a group goes idle
/// in its parent only with its last CPU; no CPU but the last to go idle is
/// told to wake, and the last gets the earliest global timer of all.
/// Waking one CPU makes it migrator all the way up, and its next event then
/// covers every idle CPU's timers.
fn smoke_tmigr_deactivate_propagates_first_expiry() -> TestResult {
    let h = Box::new(Tmigr::new());
    for cpu in 0..16 {
        h.cpu_online(cpu, Some(cpu as u64 / 4), Some(cpu as u32 / 8));
    }
    if !h.is_group_migrator(0) {
        return TestResult::Fail("the first CPU of a group is not its migrator");
    }
    // CPU 0 (the migrator) idles: CPU 1 takes over.
    if h.deactivate(0, 5000) != Some(NONE) || !h.is_group_migrator(1) {
        return TestResult::Fail("the migrator role was not handed to an active sibling");
    }
    // Every other CPU idles, each with a later timer than CPU 5's.
    let order = [1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    for &cpu in &order {
        if h.deactivate(cpu, 9000 + cpu as u64) != Some(NONE) {
            return TestResult::Fail("a CPU that was not the last to idle was told to wake");
        }
    }
    // CPU 5 is the last active CPU: it wakes for the earliest of all (CPU 0's).
    let wake = h.deactivate(5, 7000);
    if wake != Some(5000) || h.root_next_expiry() != 5000 {
        return TestResult::Fail("the last CPU to idle was not given the first global timer");
    }
    if h.global_next_for(3) != NONE {
        return TestResult::Fail("an idle CPU that is not last would wake for global timers");
    }
    // CPU 12 wakes: migrator of its group, node group, fan-in and root.
    h.activate(12);
    if !h.is_group_migrator(12) || h.global_next_for(12) > 5000 {
        return TestResult::Fail("a waking CPU did not take over the idle CPUs' timers");
    }
    // Its own timer, earlier than all, re-queued as an idle CPU's (new_timer).
    if h.deactivate(9, 1000) != Some(NONE) || h.global_next_for(12) != 1000 {
        return TestResult::Fail("an idle CPU's new timer did not reach the migrator");
    }
    if h.__validate().is_err() {
        return TestResult::Fail("hierarchy invariants broken");
    }
    TestResult::Pass
}
kernel_test_in!("time/tmigr", smoke_tmigr_deactivate_propagates_first_expiry);

#[repr(C)]
struct Fired {
    timer: TimerList,
    count: AtomicUsize,
    cpu: AtomicUsize,
}

fn fired_fn(r: timer::TimerRef) {
    // SAFETY: only `Fired` uses this callback; `timer` is its first field;
    // the test keeps it alive.
    let f = unsafe { &*(r.as_ptr() as *const Fired) };
    f.cpu
        .store(narf_lib::percpu::current_cpu(), Ordering::Release);
    f.count.fetch_add(1, Ordering::AcqRel);
}

/// An idle CPU's GLOBAL timer is run by the migrator's softirq walk — here a
/// CPU in another cache group, so the walk climbs to the node group — while
/// the idle CPU stays idle; afterwards its event is gone and its next one
/// (a second, later timer) is queued in its place.
fn smoke_tmigr_idle_cpu_global_timer_runs_on_migrator() -> TestResult {
    let Some([idle, migrator]) = dead_cpus::<2>() else {
        return TestResult::Skip("needs two CPU indices that never came online");
    };
    timer::timers_prepare_cpu(idle);
    let h = Box::new(Tmigr::new());
    h.cpu_online(migrator, Some(1), Some(0));
    h.cpu_online(idle, Some(2), Some(0));
    let mk = || {
        Box::new(Fired {
            timer: TimerList::new(fired_fn, 0),
            count: AtomicUsize::new(0),
            cpu: AtomicUsize::new(usize::MAX),
        })
    };
    let (soon, later) = (mk(), mk());
    let j = timer::jiffies();
    // SAFETY: the Boxes outlive the timers; deleted below.
    unsafe {
        timer::add_timer_on(&soon.timer, j + 2, idle);
        timer::add_timer_on(&later.timer, j + 100_000, idle);
    }
    let first = timer::global_next(idle);
    let woke_for = h.deactivate(idle, first);
    let handed = h.global_next_for(migrator) == first;
    let end = crate::monotonic_ns() + 500_000_000;
    let mut ran = 0;
    while soon.count.load(Ordering::Acquire) == 0 && crate::monotonic_ns() < end {
        ran += h.handle_remote(migrator, timer::jiffies());
        core::hint::spin_loop();
    }
    let still_idle = !h.cpu_active(idle);
    let requeued = h.global_next_for(migrator);
    timer::del_timer_sync(&soon.timer);
    timer::del_timer_sync(&later.timer);
    if woke_for != Some(NONE) {
        return TestResult::Fail("an idle CPU with an active migrator was told to wake");
    }
    if !handed {
        return TestResult::Fail("the migrator's next event missed the idle CPU's timer");
    }
    if soon.count.load(Ordering::Acquire) != 1 || ran != 1 {
        return TestResult::Fail("the migrator did not run the idle CPU's due timer once");
    }
    if soon.cpu.load(Ordering::Acquire) != narf_lib::percpu::current_cpu() {
        return TestResult::Fail("the idle CPU's timer did not run on the migrator");
    }
    if !still_idle || later.count.load(Ordering::Acquire) != 0 {
        return TestResult::Fail("the idle CPU left idle or a later timer fired early");
    }
    if requeued <= first || requeued == NONE {
        return TestResult::Fail("the idle CPU's next timer was not requeued");
    }
    if h.__validate().is_err() {
        return TestResult::Fail("hierarchy invariants broken");
    }
    TestResult::Pass
}
kernel_test_in!(
    "time/tmigr",
    smoke_tmigr_idle_cpu_global_timer_runs_on_migrator
);

/// The last CPU to go idle is woken for the hierarchy's first timer and, in
/// its softirq, runs another idle CPU's due timer without that CPU waking.
fn smoke_tmigr_last_idle_cpu_covers_all() -> TestResult {
    let Some([a, b]) = dead_cpus::<2>() else {
        return TestResult::Skip("needs two CPU indices that never came online");
    };
    timer::timers_prepare_cpu(a);
    let h = Box::new(Tmigr::new());
    h.cpu_online(a, Some(3), Some(1));
    h.cpu_online(b, Some(4), Some(2));
    let t = Box::new(Fired {
        timer: TimerList::new(fired_fn, 0),
        count: AtomicUsize::new(0),
        cpu: AtomicUsize::new(usize::MAX),
    });
    // SAFETY: the Box outlives the timer; deleted below.
    unsafe { timer::add_timer_on(&t.timer, timer::jiffies() + 2, a) };
    let exp = timer::global_next(a);
    let a_wake = h.deactivate(a, exp);
    let b_wake = h.deactivate(b, NONE);
    let end = crate::monotonic_ns() + 500_000_000;
    while t.count.load(Ordering::Acquire) == 0 && crate::monotonic_ns() < end {
        let _ = h.handle_remote(b, timer::jiffies());
        core::hint::spin_loop();
    }
    timer::del_timer_sync(&t.timer);
    if a_wake != Some(NONE) || b_wake != Some(exp) {
        return TestResult::Fail("the last CPU to idle was not the one woken for the first timer");
    }
    if t.count.load(Ordering::Acquire) != 1 || h.cpu_active(a) {
        return TestResult::Fail("the last idle CPU did not run the other idle CPU's timer");
    }
    TestResult::Pass
}
kernel_test_in!("time/tmigr", smoke_tmigr_last_idle_cpu_covers_all);
