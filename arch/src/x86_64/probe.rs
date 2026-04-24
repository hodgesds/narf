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
static PROBE_ERROR:        AtomicU64 = AtomicU64::new(0);

/// What the probe caught.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Caught {
    /// 0 if nothing fired; otherwise the CPU-exception vector number.
    pub vector:     Option<u32>,
    /// The CPU-pushed error code for vectors that push one (8, 10-14,
    /// 17, 21, 29, 30). Meaningless otherwise.
    pub error_code: u64,
}

/// Arm the probe. The next CPU exception (any vector) redirects to
/// `recovery_rip` instead of panicking, and stores the vector +
/// error code in the caught slot.
///
/// Clears any stale caught state from a prior arming.
pub fn arm(recovery_rip: u64) {
    PROBE_CAUGHT.store(0, Ordering::Release);
    PROBE_ERROR .store(0, Ordering::Release);
    PROBE_RECOVERY_RIP.store(recovery_rip, Ordering::Release);
}

/// Disarm the probe and return what was caught.
pub fn disarm() -> Caught {
    PROBE_RECOVERY_RIP.store(0, Ordering::Release);
    let raw = PROBE_CAUGHT.swap(0, Ordering::AcqRel);
    let err = PROBE_ERROR.swap(0, Ordering::AcqRel);
    Caught {
        vector: if raw == 0 { None } else { Some(raw - 1) },
        error_code: err,
    }
}

/// Consume the probe from the trap-handler side.
///
/// If a probe is armed, this atomically clears it, records the caught
/// vector + error code, and returns the recovery RIP. Otherwise
/// returns 0.
///
/// Only the trap handler should call this.
#[doc(hidden)]
pub fn consume(vector: u32, error_code: u64) -> u64 {
    let recovery = PROBE_RECOVERY_RIP.swap(0, Ordering::AcqRel);
    if recovery != 0 {
        PROBE_CAUGHT.store(vector + 1, Ordering::Release);
        PROBE_ERROR.store(error_code, Ordering::Release);
    }
    recovery
}
