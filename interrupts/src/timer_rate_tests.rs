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

use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_kernel_test::{kernel_test_in, TestResult};

/// Timer interrupts per second an idle CPU may take.
const PER_CPU_IDLE_MAX: u64 = 250;
/// Time for the APs to go idle with the tick stopped.
const SETTLE_NS: u64 = 200_000_000;
/// Sampling window.
const WINDOW_NS: u64 = 3_000_000_000;

fn spin_for(ns: u64) {
    let end = narf_time::monotonic_ns() + ns;
    while narf_time::monotonic_ns() < end {
        core::hint::spin_loop();
    }
}

/// Print `cpu`'s queued hrtimers with their arm sites and tasks.
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

#[cfg(not(target_arch = "x86_64"))]
fn kick(_mask: u64) {}

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
