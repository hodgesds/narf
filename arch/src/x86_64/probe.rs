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

use narf_lib::percpu::MAX_CPUS;

/// Per-CPU probe state. A single CPU probes + catches on its own
/// cell; there's no cross-CPU visibility needed (a CPU's probe is
/// consumed by that CPU's trap handler). Using `[const { … }; N]`
/// because `AtomicU*` isn't `Copy`, so `PerCpu<AtomicU*>` can't
/// repeat-initialise.
#[derive(Debug)]
struct ProbeCell {
    recovery: AtomicU64,
    caught: AtomicU32,
    error: AtomicU64,
}

impl ProbeCell {
    const NEW: Self = Self {
        recovery: AtomicU64::new(0),
        caught: AtomicU32::new(0),
        error: AtomicU64::new(0),
    };
}

static PROBE: [ProbeCell; MAX_CPUS] = [const { ProbeCell::NEW }; MAX_CPUS];

#[inline]
fn probe_for(cpu: usize) -> &'static ProbeCell {
    &PROBE[if cpu < MAX_CPUS { cpu } else { 0 }]
}

#[inline]
fn this_probe() -> &'static ProbeCell {
    let cpu = crate::current_cpu_id().raw() as usize;
    // Stage 2: single-CPU always returns 0; the clamp guards Stage-3
    // where MAX_CPUS could be exceeded by a mis-configured AP.
    probe_for(cpu)
}

/// What the probe caught.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Caught {
    /// 0 if nothing fired; otherwise the CPU-exception vector number.
    pub vector: Option<u32>,
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
    arm_for_cpu(crate::current_cpu_id().raw() as usize, recovery_rip);
}

/// Arm the probe cell for an already-pinned CPU.  Guarded user copies disable
/// IRQs before resolving the CPU once, then reuse that stable index for their
/// marker and probe state instead of executing RDTSCP for each access.
#[inline]
pub(super) fn arm_for_cpu(cpu: usize, recovery_rip: u64) {
    let cell = probe_for(cpu);
    cell.caught.store(0, Ordering::Release);
    cell.error.store(0, Ordering::Release);
    cell.recovery.store(recovery_rip, Ordering::Release);
}

/// Disarm the probe and return what was caught.
pub fn disarm() -> Caught {
    disarm_for_cpu(crate::current_cpu_id().raw() as usize)
}

/// Disarm the probe cell for an already-pinned CPU.  See [`arm_for_cpu`].
#[inline]
pub(super) fn disarm_for_cpu(cpu: usize) -> Caught {
    let cell = probe_for(cpu);
    cell.recovery.store(0, Ordering::Release);
    let raw = cell.caught.swap(0, Ordering::AcqRel);
    let err = cell.error.swap(0, Ordering::AcqRel);
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
    let cell = this_probe();
    let recovery = cell.recovery.swap(0, Ordering::AcqRel);
    if recovery != 0 {
        cell.caught.store(vector + 1, Ordering::Release);
        cell.error.store(error_code, Ordering::Release);
    }
    recovery
}
