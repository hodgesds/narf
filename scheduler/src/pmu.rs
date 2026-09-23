//! PMU work-cycle clock for `QuantumUnit::Cycles`.
//!
//! Linux uses APERF/MPERF for frequency-invariant accounting; NARF measures a
//! `Cycles`-quantum task's slice in ACTUAL (frequency-scaled, unhalted) core
//! cycles read from APERF. A task therefore gets the same amount of COMPUTATION
//! per slice regardless of the core's P-state — genuinely distinct from the
//! wall-time `Nanos` base, which is just TSC.
//!
//! APERF is a dedicated MSR (read via RDPRU on AMD, RDMSR otherwise), entirely
//! outside the general-purpose PMU counter pool, so it is multiplexing-free and
//! never contends with `perf_event_open`. Feature-gated (`pmu`), off by default.
//! The fixed-counter / GP-PMC fallback tiers + the unified counter-reservation
//! registry (for the rare hardware without APERF) are a deferred follow-up.

use core::sync::atomic::{AtomicU8, Ordering};

/// Cached APERF-availability probe: 0 = unknown, 1 = available, 2 = absent.
static AVAILABLE: AtomicU8 = AtomicU8::new(0);

/// IA32_APERF — the guarded-read fallback probe target.
#[cfg(target_arch = "x86_64")]
const MSR_APERF: u32 = 0x0000_00E8;

/// Whether an APERF work-cycle clock is usable on this machine. Probed once and
/// cached. VM-safe: RDPRU support (AMD) means APERF reads never `#GP`; otherwise
/// a guarded `rdmsr_or_gp(APERF)` confirms the MSR is present (some hypervisors
/// under-report the CPUID bit, so the guarded read is authoritative).
pub(crate) fn available() -> bool {
    match AVAILABLE.load(Ordering::Acquire) {
        1 => return true,
        2 => return false,
        _ => {}
    }
    let ok = probe();
    AVAILABLE.store(if ok { 1 } else { 2 }, Ordering::Release);
    ok
}

#[cfg(target_arch = "x86_64")]
fn probe() -> bool {
    // RDPRU (AMD) reads APERF at any CPL without faulting.
    if narf_arch::x86_64::rdpru::supported() {
        return true;
    }
    // Otherwise confirm the APERF MSR is actually readable (guarded — survives a
    // `#GP` on a hypervisor that does not expose it).
    narf_arch::x86_64::msr::rdmsr_or_gp(MSR_APERF).is_ok()
}

#[cfg(not(target_arch = "x86_64"))]
fn probe() -> bool {
    false
}

/// Read the current APERF work-cycle count. Only called after [`available`] has
/// confirmed a usable source, at CPL 0.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn read_work_cycles() -> u64 {
    // SAFETY: gated by `available()` (RDPRU supported, or APERF MSR present) and
    // the scheduler runs at CPL 0.
    unsafe { narf_arch::x86_64::rdpru::read_aperf() }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub(crate) fn read_work_cycles() -> u64 {
    0
}
