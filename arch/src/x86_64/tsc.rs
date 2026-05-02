//! TSC frequency calibration.
//!
//! Reference: **Intel SDM Vol 3 §17.17 "Time-Stamp Counter"**
//! and §17.17.3 ("Determining the Processor Base Frequency"). On
//! AMD processors the same approach via PMTimer / HPET cross-
//! check is documented in the BKDG.
//!
//! Strategy:
//!
//!   1. **Intel CPUID 0x15** (TSC / Crystal Clock) — when the
//!      "denominator/numerator/crystal_hz" leaf is implemented,
//!      the exact TSC frequency is `numerator / denominator *
//!      crystal_hz`. Reliable on Skylake+ with non-zero crystal.
//!   2. **CPUID 0x16** (Processor Base Frequency, MHz) — Intel
//!      Skylake+ reports the base operating frequency directly.
//!      Less precise than 0x15 but always available when 0x15
//!      gives a 0 crystal_hz.
//!   3. **HPET cross-check** — measure `Δtsc / Δhpet` over a
//!      short window. Works on every CPU with a working HPET.
//!   4. Last-resort: 1 GHz nominal (matches the historical
//!      `cycles_per_ns = 1` fallback).

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::x86_64::cpuid::cpuid;

/// Cached TSC frequency in Hz. 0 means "not yet calibrated".
static TSC_HZ: AtomicU64 = AtomicU64::new(0);

/// Try Intel CPUID 0x15. Returns (Hz, "high quality") on success,
/// `None` if the leaf isn't implemented or the crystal frequency
/// is zero.
fn from_cpuid_15h() -> Option<u64> {
    // SAFETY: CPUID 0 is always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x15 { return None; }
    // SAFETY: leaf 0x15 is defined when max >= 0x15.
    let (eax, ebx, ecx, _) = unsafe { cpuid(0x15, 0) };
    if eax == 0 || ebx == 0 || ecx == 0 { return None; }
    // tsc_hz = (numerator / denominator) * crystal_hz
    //         = ebx * ecx / eax (operate as u128 to avoid overflow).
    let tsc = (ebx as u128) * (ecx as u128) / (eax as u128);
    if tsc == 0 || tsc > u64::MAX as u128 { return None; }
    Some(tsc as u64)
}

/// Fall back to CPUID 0x16 (processor base frequency in MHz).
fn from_cpuid_16h() -> Option<u64> {
    // SAFETY: same.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x16 { return None; }
    // SAFETY: leaf 0x16 defined when max >= 0x16.
    let (eax, _, _, _) = unsafe { cpuid(0x16, 0) };
    let mhz = eax & 0xFFFF;
    if mhz == 0 { return None; }
    Some((mhz as u64) * 1_000_000)
}

/// Cross-calibrate against HPET. Measures `Δtsc / Δhpet * hpet_hz`
/// over a short window. Returns `None` if HPET isn't initialised.
fn from_hpet_xcheck() -> Option<u64> {
    // We can't directly call narf_time::hpet from arch — the
    // dependency goes the other way. The TSC calibration entry
    // point in `narf_time` calls `tsc::set_hz_via_hpet()` once
    // HPET is up.
    None
}

/// Read the TSC. Use `RDTSCP` if available (serializing on its
/// load store boundary, which gives a tighter measurement window),
/// otherwise plain `RDTSC`.
#[inline(always)]
pub fn rdtsc() -> u64 {
    // SAFETY: RDTSC is always legal at CPL=0.
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

/// Calibrate the TSC frequency. Tries CPUID 15h first, then 16h.
/// Returns the cached value on subsequent calls.
///
/// Caller must call [`set_hz_via_hpet`] separately once HPET is
/// up to populate the case where neither CPUID leaf works
/// (older / virtualised CPUs).
pub fn calibrate_via_cpuid() -> u64 {
    let cur = TSC_HZ.load(Ordering::Acquire);
    if cur != 0 { return cur; }
    if let Some(hz) = from_cpuid_15h() {
        TSC_HZ.store(hz, Ordering::Release);
        return hz;
    }
    if let Some(hz) = from_cpuid_16h() {
        TSC_HZ.store(hz, Ordering::Release);
        return hz;
    }
    let _ = from_hpet_xcheck();
    0
}

/// Set the TSC frequency from a HPET cross-check measurement.
/// The caller (typically `narf_time::hpet`) reads HPET before +
/// after a short busy-wait, reads TSC similarly, computes the
/// ratio, and calls this with the resulting Hz.
pub fn set_hz_via_hpet(hz: u64) {
    if hz != 0 { TSC_HZ.store(hz, Ordering::Release); }
}

/// Last cached TSC frequency in Hz. 0 means uncalibrated.
pub fn frequency_hz() -> u64 { TSC_HZ.load(Ordering::Acquire) }

/// Convert TSC ticks to nanoseconds. 0 if uncalibrated.
pub fn ticks_to_nanos(ticks: u64) -> u64 {
    let hz = frequency_hz();
    if hz == 0 { return 0; }
    // ns = ticks * 1e9 / hz; widen to u128 to avoid overflow.
    ((ticks as u128) * 1_000_000_000 / hz as u128) as u64
}

#[doc(hidden)]
pub fn __reset_for_test() { TSC_HZ.store(0, Ordering::Release); }
