//! aarch64 generic-timer programming.

use core::sync::atomic::{AtomicU64, Ordering};

use narf_arch::aarch64::sysreg;

/// Monotonic counter incremented on each timer-PPI delivery.
static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Start the physical timer with a countdown of `tval_ticks` counter
/// ticks. When the counter reaches zero the GIC delivers INTID 30.
///
/// # Safety
/// `init_bsp` (GICv3) must have run first.
pub unsafe fn start_timer(tval_ticks: u64) {
    // SAFETY: writes to CNTP_TVAL_EL0 and CNTP_CTL_EL0 are always
    // legal at EL1.
    unsafe {
        sysreg::write_cntp_tval_el0(tval_ticks);
        // Enable (bit 0), unmask (bit 1 = 0).
        sysreg::write_cntp_ctl_el0(1);
    }
}

/// Re-arm the timer for another `tval_ticks`. Called from the IRQ
/// handler to make the timer periodic.
///
/// # Safety
/// Must be in the IRQ handler for INTID 30.
#[inline]
pub unsafe fn rearm_timer(tval_ticks: u64) {
    // SAFETY: see `start_timer`.
    unsafe { sysreg::write_cntp_tval_el0(tval_ticks); }
}

/// Mask + disable the timer. Used on shutdown.
///
/// # Safety
/// Always safe; stops subsequent IRQ deliveries.
pub unsafe fn stop_timer() {
    // SAFETY: writes to CNTP_CTL_EL0 are always legal.
    unsafe {
        sysreg::write_cntp_ctl_el0(1 << 1);  // IMASK = 1
    }
}

/// Called from the generic-timer IRQ handler.
#[inline]
pub fn on_timer_tick() {
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot of tick count since boot.
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}
