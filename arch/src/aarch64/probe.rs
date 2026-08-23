//! Recoverable-trap probe state (aarch64).
//!
//! Direct mirror of `crate::x86_64::probe`. Linux-style exception-table
//! pattern: arm a probe with a recovery PC (an ELR value), perform a
//! potentially-faulting access, then check whether the fault was caught.
//! On catch, the EL1 data-abort handler rewrites the saved `ELR` on the
//! trap frame to the recovery address and returns, so `eret` resumes at
//! the recovery instead of the fatal diagnostic path.
//!
//! Single-probe-at-a-time, per-CPU model — mirrors the x86_64 constraint
//! exactly: the armed window runs with IRQs masked so no context switch
//! can clobber the single per-CPU slot while it is live.
//!
//! `frame/` owns the actual data-abort handler and consumes this state
//! (see `frame/src/aarch64/trap.rs`, the `EC_DATA_ABORT_CURRENT_EL` arm).

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use narf_lib::percpu::MAX_CPUS;

/// Per-CPU probe state. A single CPU probes + catches on its own cell;
/// there's no cross-CPU visibility needed (a CPU's probe is consumed by
/// that CPU's data-abort handler). Using `[const { … }; N]` because
/// `AtomicU*` isn't `Copy`.
#[derive(Debug)]
struct ProbeCell {
    recovery: AtomicU64,
    caught: AtomicU32,
    esr: AtomicU64,
}

impl ProbeCell {
    const NEW: Self = Self {
        recovery: AtomicU64::new(0),
        caught: AtomicU32::new(0),
        esr: AtomicU64::new(0),
    };
}

static PROBE: [ProbeCell; MAX_CPUS] = [const { ProbeCell::NEW }; MAX_CPUS];

#[inline]
fn this_probe() -> &'static ProbeCell {
    let cpu = crate::current_cpu_id().raw() as usize;
    // Single-CPU always returns 0; the clamp guards a mis-configured AP
    // once SMP aarch64 bring-up starts writing real ids.
    &PROBE[if cpu < MAX_CPUS { cpu } else { 0 }]
}

/// What the probe caught.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Caught {
    /// `true` iff a data abort was redirected to the armed recovery.
    pub fired: bool,
    /// The full `ESR_EL1` of the caught abort. Meaningless when
    /// `fired == false`.
    pub esr: u64,
}

/// Arm the probe. The next EL1 data abort (that isn't otherwise healable)
/// redirects to `recovery_pc` instead of taking the fatal path, and
/// records that it fired plus the abort `ESR_EL1`.
///
/// Clears any stale caught state from a prior arming.
pub fn arm(recovery_pc: u64) {
    let cell = this_probe();
    cell.caught.store(0, Ordering::Release);
    cell.esr.store(0, Ordering::Release);
    cell.recovery.store(recovery_pc, Ordering::Release);
}

/// Disarm the probe and return what was caught.
pub fn disarm() -> Caught {
    let cell = this_probe();
    cell.recovery.store(0, Ordering::Release);
    let raw = cell.caught.swap(0, Ordering::AcqRel);
    let esr = cell.esr.swap(0, Ordering::AcqRel);
    Caught {
        fired: raw != 0,
        esr,
    }
}

/// Whether a probe is currently armed on this CPU.
///
/// The data-abort handler consults this *before* attempting any healing
/// arm so the heal-first / fixup-last ordering can be preserved: it only
/// matters that a probe is armed, not what it recovers to.
#[inline]
pub fn is_armed() -> bool {
    this_probe().recovery.load(Ordering::Acquire) != 0
}

/// Consume the probe from the data-abort-handler side.
///
/// If a probe is armed, this atomically clears it, records that it fired
/// plus the abort `ESR_EL1`, and returns the recovery PC. Otherwise
/// returns 0.
///
/// Only the data-abort handler should call this, and only after every
/// legitimate healing arm (demand paging, stack grow, COW split) has been
/// given the fault first — mirroring the x86_64 heal-first ordering.
#[doc(hidden)]
pub fn consume(esr: u64) -> u64 {
    let cell = this_probe();
    let recovery = cell.recovery.swap(0, Ordering::AcqRel);
    if recovery != 0 {
        cell.caught.store(1, Ordering::Release);
        cell.esr.store(esr, Ordering::Release);
    }
    recovery
}
