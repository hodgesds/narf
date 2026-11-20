//! Idle local-timer interrupt rate (`time/idle-rate`).
//!
//! An idle Linux desktop takes 28–201 local timer interrupts per CPU per
//! second (`LOC` in `/proc/interrupts`, 764/s over 12 CPUs, measured on the
//! same Ryzen 7600X machine NARF's hardware numbers come from): with NOHZ
//! idle the tick stops and a CPU wakes only for its own timers, which
//! periodic kernel housekeeping keeps sparse (`round_jiffies`, deferrable
//! timers, interrupt-driven drivers). This smoke turns tickless idle on as a
//! normal boot has it, lets every application processor go idle, and counts
//! each one's timer interrupts over a few seconds. Each must stay under
//! [`PER_CPU_IDLE_MAX`]: Linux's worst idle CPU above with room for a guest's
//! virtual timer, and an order of magnitude below one 1 ms or 10 ms poller
//! (1000/s, 100/s). The boot CPU runs the harness (its timer is stopped in a
//! kernel-test boot) and is not measured. A CPU over the bound prints the
//! owners of the hrtimers it has queued, `/proc/timer_list` style, so the
//! failure names the poller.

extern crate alloc;

#[cfg(target_arch = "x86_64")]
use alloc::vec::Vec;
#[cfg(target_arch = "x86_64")]
use core::fmt::Write as _;

use narf_kernel_test::{kernel_test_in, TestResult};

/// Timer interrupts per second an idle CPU may take.
#[cfg(target_arch = "x86_64")]
const PER_CPU_IDLE_MAX: u64 = 250;
/// Time for the APs to go idle with the tick stopped.
#[cfg(target_arch = "x86_64")]
const SETTLE_NS: u64 = 200_000_000;
/// Sampling window.
#[cfg(target_arch = "x86_64")]
const WINDOW_NS: u64 = 3_000_000_000;

#[cfg(target_arch = "x86_64")]
fn spin_for(ns: u64) {
    let end = narf_time::monotonic_ns() + ns;
    while narf_time::monotonic_ns() < end {
        core::hint::spin_loop();
    }
}

/// Print `cpu`'s queued hrtimers with their arm sites and tasks.
#[cfg(target_arch = "x86_64")]
fn dump_timers(cpu: usize) {
    let mut w = narf_console::Writer;
    let _ = writeln!(w, "  idle-rate: cpu {} queued hrtimers:", cpu);
    for index in 0..narf_time::hrtimer::HRTIMER_MAX_CLOCK_BASES {
        let mut snap = Vec::new();
        narf_time::hrtimer::snapshot_base(cpu, index, &mut snap);
        for t in snap {
            match t.site {
                Some(l) => {
                    let _ = writeln!(
                        w,
                        "    base {} fn {:#x} task {} {}:{} range {} ns",
                        index,
                        t.function,
                        t.owner_task,
                        l.file(),
                        l.line(),
                        t.expires - t.softexpires
                    );
                }
                None => {
                    let _ = writeln!(w, "    base {} fn {:#x}", index, t.function);
                }
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn kick(mask: u64) {
    crate::x86_64::apic::send_fixed_ipi(mask, crate::VECTOR_RESCHED);
}

fn smoke_idle_timer_interrupt_rate_is_linux_like() -> TestResult {
    #[cfg(not(target_arch = "x86_64"))]
    {
        TestResult::Skip("counts the x86 LAPIC timer vector")
    }
    #[cfg(target_arch = "x86_64")]
    {
        let me = narf_lib::percpu::current_cpu();
        let aps: Vec<usize> = (0..narf_lib::percpu::MAX_CPUS
            .min(crate::dispatch::PERCPU_FIRES_MAX))
            .filter(|&c| c != me && narf_lib::smp::is_online(c as u32))
            .filter(|&c| crate::x86_64::apic::local_timer_mode(c).is_oneshot())
            .collect();
        if aps.is_empty() {
            return TestResult::Skip("no AP runs a one-shot LAPIC tick");
        }
        let mask = aps.iter().fold(0u64, |m, &c| m | (1u64 << c));
        let nohz_was = narf_time::nohz_idle_enabled();
        // A normal boot runs tickless idle (`nohz` defaults on); the APs pick
        // it up the next time they go idle.
        narf_time::set_nohz_idle_enabled(true);
        kick(mask);
        spin_for(SETTLE_NS);
        let count = |c: usize| crate::fire_count_on_cpu(crate::VECTOR_TIMER, c);
        let before: Vec<u64> = aps.iter().map(|&c| count(c)).collect();
        let t0 = narf_time::monotonic_ns();
        spin_for(WINDOW_NS);
        let elapsed_ms = (narf_time::monotonic_ns() - t0) / 1_000_000;
        let after: Vec<u64> = aps.iter().map(|&c| count(c)).collect();
        narf_time::set_nohz_idle_enabled(nohz_was);
        // Every AP restarts the tick the harness boot runs it with.
        kick(mask);
        let mut w = narf_console::Writer;
        let mut over = Vec::new();
        let _ = write!(
            w,
            "  idle-rate: timer IRQs/s per idle AP over {} ms:",
            elapsed_ms
        );
        for (i, &cpu) in aps.iter().enumerate() {
            let rate = (after[i] - before[i]) * 1_000 / elapsed_ms.max(1);
            let _ = write!(w, " {}:{}", cpu, rate);
            if rate > PER_CPU_IDLE_MAX {
                over.push(cpu);
            }
        }
        let _ = writeln!(w);
        if over.is_empty() {
            return TestResult::Pass;
        }
        for &cpu in &over {
            dump_timers(cpu);
        }
        TestResult::Fail("an idle CPU takes more timer interrupts than an idle Linux CPU")
    }
}
kernel_test_in!(
    "time/idle-rate",
    smoke_idle_timer_interrupt_rate_is_linux_like
);

/// A busy CPU takes `HZ` ticks a second (`time/tick-rate`), as Linux's
/// `tick_sched_timer` gives every CPU: once the TSC is calibrated,
/// `retune_local_ticks` sets each application processor's one-shot tick to
/// the boot CPU's 1000 Hz (they start before calibration, from an
/// uncalibrated scale). An AP kept busy by a pinned spinning task must then
/// take 1000 ± 20 % timer interrupts a second.
#[cfg(target_arch = "x86_64")]
fn smoke_busy_ap_ticks_at_hz() -> TestResult {
    use crate::x86_64::apic;
    use core::sync::atomic::{AtomicBool, Ordering};
    static SPIN: AtomicBool = AtomicBool::new(false);
    static RUNNING: AtomicBool = AtomicBool::new(false);
    let me = narf_lib::percpu::current_cpu();
    let Some(ap) =
        (0..narf_lib::percpu::MAX_CPUS.min(crate::dispatch::PERCPU_FIRES_MAX)).find(|&c| {
            c != me && narf_lib::smp::is_online(c as u32) && apic::local_timer_mode(c).is_oneshot()
        })
    else {
        return TestResult::Skip("no AP runs a one-shot LAPIC tick");
    };
    SPIN.store(true, Ordering::Release);
    RUNNING.store(false, Ordering::Release);
    narf_scheduler::spawn_stackful_pinned(
        async {
            RUNNING.store(true, Ordering::Release);
            while SPIN.load(Ordering::Acquire) {
                core::hint::spin_loop();
            }
            RUNNING.store(false, Ordering::Release);
        },
        ap as u32,
    );
    kick(1u64 << ap);
    let started = narf_time::monotonic_ns() + 1_000_000_000;
    while !RUNNING.load(Ordering::Acquire) && narf_time::monotonic_ns() < started {
        core::hint::spin_loop();
    }
    if !RUNNING.load(Ordering::Acquire) {
        SPIN.store(false, Ordering::Release);
        return TestResult::Skip("the pinned busy task never ran on the AP");
    }
    let count = || crate::fire_count_on_cpu(crate::VECTOR_TIMER, ap);
    let rate_over = |ns: u64| {
        let before = count();
        let t0 = narf_time::monotonic_ns();
        spin_for(ns);
        let elapsed_ms = (narf_time::monotonic_ns() - t0) / 1_000_000;
        (count() - before) * 1_000 / elapsed_ms.max(1)
    };
    // The tick the AP started with at bring-up, before calibration.
    let boot_rate = rate_over(300_000_000);
    let _ = apic::retune_local_ticks(1000);
    let retuned = apic::local_tick_period_cycles(ap) == apic::tick_period_cycles_for(1000);
    // Let the AP adopt the period at its next ticks, then measure.
    spin_for(50_000_000);
    let rate = rate_over(500_000_000);
    SPIN.store(false, Ordering::Release);
    let _ = writeln!(
        narf_console::Writer,
        "  tick-rate: busy AP {} takes {} timer IRQs/s with its bring-up tick, {} at HZ",
        ap,
        boot_rate,
        rate
    );
    if !retuned {
        return TestResult::Fail("an AP's tick was not retuned to 1000 Hz");
    }
    if !(800..=1200).contains(&rate) {
        return TestResult::Fail("a busy AP does not tick at HZ");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("time/tick-rate", smoke_busy_ap_ticks_at_hz);
