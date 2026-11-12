//! Cross-CPU race smoke for the timer migration hierarchy (`time/tmigr`).
//!
//! Real APs race `activate` / `deactivate` / `handle_remote` on one private
//! [`Tmigr`] while arming GLOBAL wheel timers. Each AP drives one logical
//! hierarchy CPU — an index no core ever ran on, so the kernel's own
//! hierarchy and timers are untouched and nothing but this test ever runs
//! that index's wheel. An AP plays its logical CPU exactly as the kernel
//! would: while active it runs its own expired timers and migrates for its
//! groups; it idles with its next global timer handed to the hierarchy; an
//! idle CPU told to wake (`tmc->wakeup`) runs the remote expiry when that
//! event is due.
//!
//! Every timer must fire exactly once, never before its expiry, and not
//! later than the harness's own polling cadence allows; none may be lost.
//! It lives in the scheduler crate because it needs pinned tasks on APs.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::percpu::MAX_CPUS;
use narf_time::timer::{self, TimerList, TimerRef};
use narf_time::timer_migration::Tmigr;

use crate::affinity::{Affinity, CpuId};
use crate::TaskSpec;

const NONE: u64 = u64::MAX;
/// Logical CPUs (and APs) racing.
const MAX_ACTORS: usize = 4;
/// Timers each logical CPU arms, one per active period.
const TIMERS_PER_CPU: usize = 48;
/// Lateness allowed past expiry, in jiffies (1 ms): the harness polls every
/// ~2 ms; the rest is headroom for a descheduled QEMU vCPU.
const LATE_MAX: u64 = 25;

#[repr(C)]
struct Fired {
    timer: TimerList,
    expires: AtomicU64,
    fired_at: AtomicU64,
    count: AtomicU32,
}

fn fired_fn(r: TimerRef) {
    // SAFETY: only `Fired` uses this callback; `timer` is its first field
    // (`repr(C)`); the test leaks every `Fired`.
    let f = unsafe { &*(r.as_ptr() as *const Fired) };
    f.fired_at.store(timer::jiffies(), Ordering::Release);
    f.count.fetch_add(1, Ordering::AcqRel);
}

fn spin_ns(ns: u64) {
    let end = narf_time::monotonic_ns().saturating_add(ns);
    while narf_time::monotonic_ns() < end {
        core::hint::spin_loop();
    }
}

fn xorshift(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

struct Actor {
    h: &'static Tmigr,
    cpu: usize,
    timers: &'static [Fired],
    seed: u64,
    stop: &'static AtomicBool,
    armed: &'static AtomicUsize,
    done: &'static AtomicUsize,
}

async fn actor(a: Actor) {
    let mut rng = a.seed | 1;
    let mut next = 0;
    while !a.stop.load(Ordering::Acquire) {
        // Leave idle: run our own due timers (our softirq) and migrate for
        // every group we are migrator of.
        a.h.activate(a.cpu);
        let _ = timer::__expire_global_for_test(a.cpu);
        let _ = a.h.handle_remote(a.cpu, timer::jiffies());
        if let Some(t) = a.timers.get(next) {
            next += 1;
            let exp = timer::jiffies() + 1 + xorshift(&mut rng) % 6;
            t.expires.store(exp, Ordering::Release);
            // SAFETY: `t` is leaked; it is armed once.
            unsafe { timer::add_timer_on(&t.timer, exp, a.cpu) };
            a.armed.fetch_add(1, Ordering::AcqRel);
        }
        spin_ns(xorshift(&mut rng) % 100_000);
        // Enter tickless idle with our next global timer.
        let _ = a.h.deactivate(a.cpu, timer::__global_next_for_test(a.cpu));
        let idle_end = narf_time::monotonic_ns() + xorshift(&mut rng) % 2_000_000;
        while narf_time::monotonic_ns() < idle_end {
            // Idle: woken only for `tmc->wakeup` (the last CPU to idle).
            if a.h.global_next_for(a.cpu) <= timer::jiffies() {
                let _ = a.h.handle_remote(a.cpu, timer::jiffies());
            }
            core::hint::spin_loop();
        }
        crate::yield_now().await;
    }
    // Stay active: our own timers are ours to run in the final drain.
    a.h.activate(a.cpu);
    a.done.fetch_add(1, Ordering::AcqRel);
}

/// `n` CPU indices that have never been online, highest first.
fn dead_cpus(n: usize) -> Vec<usize> {
    let ever = narf_lib::smp::ever_online_bitmap();
    (1..MAX_CPUS.min(64))
        .rev()
        .filter(|c| ever & (1u64 << c) == 0)
        .take(n)
        .collect()
}

fn wait_ns(ns: u64, mut done: impl FnMut() -> bool) -> bool {
    let end = narf_time::monotonic_ns().saturating_add(ns);
    while narf_time::monotonic_ns() < end {
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    done()
}

/// APs toggle idle on a shared hierarchy while their timers are armed:
/// every GLOBAL timer fires exactly once, on time, and none is lost; the
/// hierarchy's invariants hold afterwards.
fn smoke_tmigr_cross_cpu_activate_deactivate_race() -> TestResult {
    let me = narf_lib::percpu::current_cpu();
    let live = narf_lib::smp::ever_online_bitmap() & narf_lib::smp::online_bitmap();
    let aps: Vec<usize> = (0..MAX_CPUS.min(64))
        .filter(|&c| c != me && live & (1u64 << c) != 0)
        .collect();
    let dead = dead_cpus(MAX_ACTORS);
    let n = aps.len().min(dead.len()).min(MAX_ACTORS);
    if n < 2 {
        return TestResult::Skip("needs two APs and two CPU indices that never came online");
    }
    let h: &'static Tmigr = Box::leak(Box::new(Tmigr::new()));
    for (i, &cpu) in dead[..n].iter().enumerate() {
        timer::timers_prepare_cpu(cpu);
        // Two per last-level cache: walks climb past level 0.
        h.cpu_online(cpu, Some(i as u64 / 2), Some(0));
    }
    let timers: &'static [Fired] = Box::leak(
        (0..n * TIMERS_PER_CPU)
            .map(|_| Fired {
                timer: TimerList::new(fired_fn, 0),
                expires: AtomicU64::new(NONE),
                fired_at: AtomicU64::new(NONE),
                count: AtomicU32::new(0),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    let stop: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let armed: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    let done: &'static AtomicUsize = Box::leak(Box::new(AtomicUsize::new(0)));
    for i in 0..n {
        crate::spawn_with_spec(
            actor(Actor {
                h,
                cpu: dead[i],
                timers: &timers[i * TIMERS_PER_CPU..(i + 1) * TIMERS_PER_CPU],
                seed: 0x9e37_79b9_7f4a_7c15 ^ (i as u64 + 1).wrapping_mul(0xbf58_476d),
                stop,
                armed,
                done,
            }),
            TaskSpec {
                affinity: Affinity::pinned(CpuId(aps[i] as u32)),
                ..TaskSpec::kernel_any()
            },
        );
    }
    let all = n * TIMERS_PER_CPU;
    let fired = || timers.iter().all(|t| t.count.load(Ordering::Acquire) != 0);
    let in_time = wait_ns(5_000_000_000, || {
        armed.load(Ordering::Acquire) == all && fired()
    });
    stop.store(true, Ordering::Release);
    let stopped = wait_ns(1_000_000_000, || done.load(Ordering::Acquire) == n);
    // Final drain from here: every logical CPU is active again, so anything
    // still queued is a timer the race lost track of.
    let lost_then_found = !fired()
        && wait_ns(200_000_000, || {
            for &cpu in &dead[..n] {
                let _ = timer::__expire_global_for_test(cpu);
            }
            fired()
        });
    let mut early = 0;
    let mut late = 0;
    let mut lost = 0;
    let mut doubled = 0;
    for t in timers.iter() {
        let (exp, at) = (
            t.expires.load(Ordering::Acquire),
            t.fired_at.load(Ordering::Acquire),
        );
        match t.count.load(Ordering::Acquire) {
            0 => lost += 1,
            1 => (),
            _ => doubled += 1,
        }
        if exp != NONE && at != NONE {
            if at < exp {
                early += 1;
            } else if at - exp > LATE_MAX {
                late += 1;
            }
        }
        timer::del_timer_sync(&t.timer);
    }
    let valid = h.__validate();
    for &cpu in &dead[..n] {
        h.cpu_offline(cpu);
    }
    if !stopped {
        return TestResult::Fail("an actor never finished");
    }
    if armed.load(Ordering::Acquire) != all {
        return TestResult::Fail("the actors did not arm every timer");
    }
    if doubled != 0 {
        return TestResult::Fail("a GLOBAL timer fired more than once");
    }
    if early != 0 {
        return TestResult::Fail("a GLOBAL timer fired before its expiry");
    }
    if lost != 0 || lost_then_found || !in_time {
        return TestResult::Fail("a GLOBAL timer was lost while its CPU was idle");
    }
    if late != 0 {
        return TestResult::Fail("a GLOBAL timer of an idle CPU fired late");
    }
    if valid.is_err() {
        return TestResult::Fail("hierarchy invariants broken after the race");
    }
    TestResult::Pass
}
kernel_test_in!("time/tmigr", smoke_tmigr_cross_cpu_activate_deactivate_race);
