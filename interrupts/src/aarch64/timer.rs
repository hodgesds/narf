//! aarch64 generic-timer programming.

use core::sync::atomic::{AtomicU64, Ordering};

use narf_arch::aarch64::sysreg;

/// Per-CPU monotonic counter incremented on each timer-PPI
/// delivery. Indexed by `narf_lib::percpu::current_cpu()`.
static TIMER_TICKS_PER_CPU: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];

/// Backwards-compat: aggregate across all CPUs (was `TIMER_TICKS`).
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Start the physical timer with a countdown of `tval_ticks` counter
/// ticks. When the counter reaches zero the GIC delivers INTID 30.
///
/// # Safety
/// `init_bsp` (GICv3) must have run first.
pub unsafe fn start_timer(tval_ticks: u64) {
    let cpu = narf_lib::percpu::current_cpu();
    // `hrtimers_prepare_cpu`: this CPU's base exists before its first tick.
    narf_time::hrtimer::hrtimers_prepare_cpu(cpu);
    ARMED[cpu].store(
        narf_time::now_cycles().saturating_add(tval_ticks),
        Ordering::Relaxed,
    );
    // SAFETY: writes to CNTP_TVAL_EL0 and CNTP_CTL_EL0 are always
    // legal at EL1.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        sysreg::write_cntp_tval_el0(tval_ticks);
        // Enable (bit 0), unmask (bit 1 = 0).
        sysreg::write_cntp_ctl_el0(1);
    }
    // The generic timer is this CPU's clockevent: hrtimer enqueues pull it
    // in to their event (`tick_program_event`).
    narf_time::hrtimer::set_arm_callback(arm_hrtimer_event);
}

/// Counter value this CPU's timer is programmed to fire at.
static ARMED: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(u64::MAX) }; narf_lib::percpu::MAX_CPUS];

/// Program this CPU's timer to fire in `tval` ticks from `now`.
fn program(cpu: usize, now: u64, tval: u64) {
    let tval = tval.max(1);
    ARMED[cpu].store(now.saturating_add(tval), Ordering::Relaxed);
    // SAFETY: CNTP_TVAL_EL0 writes are always legal at EL1.
    unsafe {
        sysreg::write_cntp_tval_el0(tval);
    }
}

/// `tick_program_event` for the hrtimer base: pull this CPU's timer in to
/// `deadline_cycles` (counter ticks) if that is earlier than what it is
/// programmed for. IRQ-masked so the tick handler cannot interleave.
fn arm_hrtimer_event(deadline_cycles: u64) {
    narf_lib::sync::without_interrupts(|| {
        let cpu = narf_lib::percpu::current_cpu();
        let now = narf_time::now_cycles();
        if deadline_cycles < ARMED[cpu].load(Ordering::Relaxed) {
            program(cpu, now, deadline_cycles.saturating_sub(now));
        }
    });
}

/// Re-arm the timer for another `tval_ticks`. Called from the IRQ
/// handler to make the timer periodic.
///
/// # Safety
/// Must be in the IRQ handler for INTID 30.
#[inline]
pub unsafe fn rearm_timer(tval_ticks: u64) {
    let cpu = narf_lib::percpu::current_cpu();
    let now = narf_time::now_cycles();
    // The sooner of the periodic tick and this CPU's next hrtimer event.
    let tval = narf_time::hrtimer::next_event_cycles_local()
        .map_or(tval_ticks, |next| tval_ticks.min(next.saturating_sub(now)));
    program(cpu, now, tval);
}

/// Mask + disable the timer. Used on shutdown.
///
/// # Safety
/// Always safe; stops subsequent IRQ deliveries.
pub unsafe fn stop_timer() {
    // SAFETY: writes to CNTP_CTL_EL0 are always legal.
    unsafe {
        sysreg::write_cntp_ctl_el0(1 << 1); // IMASK = 1
    }
}

/// Called from the generic-timer IRQ handler.
#[inline]
pub fn on_timer_tick() {
    let cpu = narf_lib::percpu::current_cpu();
    TIMER_TICKS_PER_CPU[cpu].fetch_add(1, Ordering::Relaxed);
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
    ARMED[cpu].store(u64::MAX, Ordering::Relaxed);
    // `hrtimer_interrupt`: expire this CPU's due hrtimers. The caller's
    // `rearm_timer` then programs the next tick or event.
    let _ = narf_time::hrtimer::hrtimer_interrupt();
}

/// Aggregate snapshot of tick count across all CPUs since boot.
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}

/// Per-CPU tick count snapshot.
pub fn timer_ticks_for(cpu_index: u32) -> u64 {
    let i = (cpu_index as usize).min(narf_lib::percpu::MAX_CPUS - 1);
    TIMER_TICKS_PER_CPU[i].load(Ordering::Relaxed)
}
