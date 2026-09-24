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
//!
//! The read SOURCE (RDPRU vs RDMSR) is probed once and cached, so the slice-check
//! hot path reads APERF with a single instruction — `rdpru::read_aperf` re-runs
//! CPUID (a serializing VM-exit under KVM) on every call, which is too costly per
//! dispatch/tick.

use core::sync::atomic::{AtomicU8, Ordering};

/// Cached APERF read source: 0 = unknown, 1 = RDPRU, 2 = absent, 3 = RDMSR.
static SOURCE: AtomicU8 = AtomicU8::new(SRC_UNKNOWN);
const SRC_UNKNOWN: u8 = 0;
const SRC_RDPRU: u8 = 1;
const SRC_ABSENT: u8 = 2;
const SRC_RDMSR: u8 = 3;

/// IA32_APERF — the RDMSR source / guarded-read probe target.
#[cfg(target_arch = "x86_64")]
const MSR_APERF: u32 = 0x0000_00E8;

/// Resolve (and cache) the APERF read source.
fn source() -> u8 {
    let cached = SOURCE.load(Ordering::Acquire);
    if cached != SRC_UNKNOWN {
        return cached;
    }
    let resolved = probe_source();
    SOURCE.store(resolved, Ordering::Release);
    resolved
}

/// Whether an APERF work-cycle clock is usable on this machine. Probed once and
/// cached. VM-safe: RDPRU support (AMD) means APERF reads never `#GP`; otherwise
/// a guarded `rdmsr_or_gp(APERF)` confirms the MSR is present (some hypervisors
/// under-report the CPUID bit, so the guarded read is authoritative).
pub(crate) fn available() -> bool {
    source() != SRC_ABSENT
}

#[cfg(target_arch = "x86_64")]
fn probe_source() -> u8 {
    // RDPRU (AMD) reads APERF at any CPL without faulting.
    if narf_arch::x86_64::rdpru::supported() {
        return SRC_RDPRU;
    }
    // Otherwise confirm the APERF MSR is actually readable (guarded — survives a
    // `#GP` on a hypervisor that does not expose it).
    if narf_arch::x86_64::msr::rdmsr_or_gp(MSR_APERF).is_ok() {
        SRC_RDMSR
    } else {
        SRC_ABSENT
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn probe_source() -> u8 {
    SRC_ABSENT
}

/// Read the current APERF work-cycle count via the cached source — no per-read
/// CPUID. Only called after [`available`] has confirmed a usable source (so
/// `SOURCE` is `RDPRU` or `RDMSR`, never `ABSENT`), at CPL 0.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) fn read_work_cycles() -> u64 {
    match SOURCE.load(Ordering::Relaxed) {
        // SAFETY: RDPRU reads APERF (ECX=1) at any CPL when supported (the cached
        // source proves it), no fault.
        SRC_RDPRU => unsafe { narf_arch::x86_64::rdpru::rdpru(1) },
        // SAFETY: the RDMSR source was established by a prior guarded
        // `rdmsr_or_gp(APERF)` probe, so the unguarded read cannot `#GP`; the
        // scheduler runs at CPL 0.
        _ => unsafe { narf_arch::x86_64::msr::rdmsr(MSR_APERF) },
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
pub(crate) fn read_work_cycles() -> u64 {
    0
}
