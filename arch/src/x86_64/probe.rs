//! Recoverable-trap probe state.
//!
//! Linux-style exception-table pattern: arm a probe with a recovery
//! RIP, perform a potentially-faulting access, then check whether the
//! fault was caught. On catch, the trap handler rewrites the saved RIP
//! on the trap frame to the recovery address and returns, so `iretq`
//! resumes at the recovery instead of panic-exiting.
//!
//! Single-probe-at-a-time model — Stage 2 BSP-only. Per-CPU probe
//! state arrives with Wave 3 SMP bring-up.
//!
//! `frame/` owns the actual trap handler and consumes this state.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static PROBE_RECOVERY_RIP: AtomicU64 = AtomicU64::new(0);
static PROBE_CAUGHT:       AtomicU32 = AtomicU32::new(0);

/// Arm the probe. The next CPU exception (any vector) redirects to
/// `recovery_rip` instead of panicking, and stores `vector + 1` in
/// the caught slot.
///
/// Clears any stale caught state from a prior arming.
pub fn arm(recovery_rip: u64) {
    PROBE_CAUGHT.store(0, Ordering::Release);
    PROBE_RECOVERY_RIP.store(recovery_rip, Ordering::Release);
}

/// Disarm the probe and return what was caught.
///
/// Return value: 0 = no fault caught; N > 0 = vector N-1 fired.
pub fn disarm() -> u32 {
    PROBE_RECOVERY_RIP.store(0, Ordering::Release);
    PROBE_CAUGHT.swap(0, Ordering::AcqRel)
}

/// Consume the probe from the trap-handler side.
///
/// If a probe is armed, this atomically clears it, records the caught
/// vector, and returns the recovery RIP. Otherwise returns 0.
///
/// Only the trap handler should call this.
#[doc(hidden)]
pub fn consume(vector: u32) -> u64 {
    let recovery = PROBE_RECOVERY_RIP.swap(0, Ordering::AcqRel);
    if recovery != 0 {
        PROBE_CAUGHT.store(vector + 1, Ordering::Release);
    }
    recovery
}
