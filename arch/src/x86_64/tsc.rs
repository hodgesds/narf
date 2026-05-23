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
//!   3. **AMD MSR_PSTATE0** (0xC001_0064) — Family 0x17+ chips
//!      don't populate Intel CPUID leaves 0x15 / 0x16. The
//!      P-state-0 definition MSR encodes the P0 (boost) clock
//!      from `CpuFid` / `CpuDfsId`; on Zen2+ the TSC is
//!      invariant and tied to that boost clock. See
//!      [`calibrate_via_amd_pstate0`].
//!   4. **HPET cross-check** — measure `Δtsc / Δhpet` over a
//!      short window. Works on every CPU with a working HPET,
//!      but unreliable on Phoenix HawkPoint1 (Zen4 mobile)
//!      where the HPET counter drifts under SMM activity.
//!   5. Last-resort: 1 GHz nominal (matches the historical
//!      `cycles_per_ns = 1` fallback).

#![cfg(target_arch = "x86_64")]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::x86_64::cpuid::cpuid;
use crate::x86_64::msr::rdmsr_or_gp;

/// Cached TSC frequency in Hz. 0 means "not yet calibrated".
static TSC_HZ: AtomicU64 = AtomicU64::new(0);

/// Try Intel CPUID 0x15. Returns (Hz, "high quality") on success,
/// `None` if the leaf isn't implemented or the crystal frequency
/// is zero.
///
/// Exposed via the doc-hidden `__from_cpuid_15h` alias so
/// `narf_time::calibrate_clocks_with_source` can probe each
/// source in turn without colliding with the cached fast-path in
/// `calibrate_via_cpuid`.
#[doc(hidden)]
pub fn __from_cpuid_15h() -> Option<u64> {
    from_cpuid_15h()
}

fn from_cpuid_15h() -> Option<u64> {
    // SAFETY: CPUID 0 is always defined.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x15 {
        return None;
    }
    // SAFETY: leaf 0x15 is defined when max >= 0x15.
    let (eax, ebx, ecx, _) = unsafe { cpuid(0x15, 0) };
    if eax == 0 || ebx == 0 || ecx == 0 {
        return None;
    }
    // tsc_hz = (numerator / denominator) * crystal_hz
    //         = ebx * ecx / eax (operate as u128 to avoid overflow).
    let tsc = (ebx as u128) * (ecx as u128) / (eax as u128);
    if tsc == 0 || tsc > u64::MAX as u128 {
        return None;
    }
    Some(tsc as u64)
}

/// Doc-hidden alias for the per-leaf probe; see
/// [`__from_cpuid_15h`] rationale.
#[doc(hidden)]
pub fn __from_cpuid_16h() -> Option<u64> {
    from_cpuid_16h()
}

/// Fall back to CPUID 0x16 (processor base frequency in MHz).
fn from_cpuid_16h() -> Option<u64> {
    // SAFETY: same.
    let max = unsafe { cpuid(0, 0).0 };
    if max < 0x16 {
        return None;
    }
    // SAFETY: leaf 0x16 defined when max >= 0x16.
    let (eax, _, _, _) = unsafe { cpuid(0x16, 0) };
    let mhz = eax & 0xFFFF;
    if mhz == 0 {
        return None;
    }
    Some((mhz as u64) * 1_000_000)
}

/// MSR index for AMD P-state-0 definition (`MSR_AMD_PSTATE_DEF_BASE`).
/// Mirrors Linux `arch/x86/include/asm/msr-index.h` and the AMD64
/// PPR / BKDG entry `Core::X86::Msr::PStateDef`.
const MSR_AMD_PSTATE_DEF_0: u32 = 0xC001_0064;

/// AMD P-state 0 frequency readout via MSR 0xC001_0064
/// (`Core::X86::Msr::PStateDef`). On AMD Family 0x17+ the TSC is
/// invariant and runs at the P0 (boost) frequency, so decoding
/// P-state 0 yields the TSC clock without needing a cross-check.
///
/// Bit layout (AMD64 PPR, Family 0x17 / 0x19):
/// ```text
///   [13:8]  CpuDfsId  — clock-divider-select (1..63; 8 = ÷1)
///   [7:0]   CpuFid    — frequency identifier
/// ```
/// Decoded as `CoreCOF = (CpuFid / CpuDfsId) * 200 MHz`. Matches
/// the formula used by Linux's `amd-pstate.c` /
/// `arch/x86/kernel/cpu/amd.c` and Xen's `amd_parse_freq()`
/// (`xen-devel` thread "fix core frequency calculation for AMD
/// Family 1Ah CPUs"). Family 0x1A (Zen5) changed the encoding to
/// `CoreCOF = CpuFid[11:0] * 5 MHz` — handled inline below.
///
/// Returns Hz on success, or 0 if:
///   - vendor isn't `AuthenticAMD`
///   - family is < 0x17 (older AMD has a different MSR layout)
///   - the MSR `#GP`'d (BIOS lock or unsupported)
///   - decoded fields would produce a divide-by-zero
///
/// Used as TSC-calibration fallback when CPUID 0x15 / 0x16 don't
/// populate (the Intel-only leaves) and HPET cross-check is
/// unreliable (Phoenix HawkPoint1 SMM drift). See `narf_time`'s
/// `calibrate_clocks` for the call order.
pub fn calibrate_via_amd_pstate0() -> u64 {
    // 1. Vendor must be "AuthenticAMD".
    // SAFETY: leaf 0 is always defined on x86_64.
    let (_, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    // "Auth" "enti" "cAMD" in little-endian register order
    // matches Linux's `x86_vendor_init_amd`.
    if !(ebx == 0x6874_7541 && edx == 0x6974_6E65 && ecx == 0x444D_4163) {
        return 0;
    }
    // 2. Decode family. Modern AMD reports base_family == 0xF, so
    //    ext_family is always in play; we still apply the
    //    Intel-style guard so older AMD (Family 0x6 K6, 0xF K8)
    //    flows through the same path.
    // SAFETY: leaf 1 is always defined.
    let (sig, _, _, _) = unsafe { cpuid(1, 0) };
    let base_family = ((sig >> 8) & 0xF) as u16;
    let ext_family = ((sig >> 20) & 0xFF) as u16;
    let family = base_family + if base_family == 0xF { ext_family } else { 0 };
    if family < 0x17 {
        return 0;
    }
    // 3. Read MSR_AMD_PSTATE_DEF_0. Use the GP-safe path so a
    //    firmware-locked / virtualised MSR surfaces as Err
    //    instead of panicking the BSP. Some hypervisors disable
    //    the entire PStateDef range — calibrate_clocks then falls
    //    back to HPET.
    let v = match rdmsr_or_gp(MSR_AMD_PSTATE_DEF_0) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    // 4. Decode CpuFid + CpuDfsId per family.
    if family >= 0x1A {
        // Zen5+: `CoreCOF = CpuFid[11:0] * 5 MHz`. No divisor.
        let cpu_fid = v & 0xFFF;
        if cpu_fid == 0 {
            return 0;
        }
        return cpu_fid.saturating_mul(5_000_000);
    }
    // Zen / Zen+ / Zen2 / Zen3 / Zen4 (Family 0x17 / 0x19):
    //   CoreCOF = (CpuFid * 200 MHz) / CpuDfsId
    //           = (CpuFid * 25 * 8) / CpuDfsId  (Xen-style)
    // 200 MHz is the FCH reference clock; CpuDfsId is the
    // divider with default 8 (= /1). At nominal P0 on a 4.0 GHz
    // Zen4: CpuFid=160, CpuDfsId=8 → 200 * 160 / 8 = 4000 MHz.
    let cpu_fid = v & 0xFF;
    let cpu_dfs_id = (v >> 8) & 0x3F;
    if cpu_fid == 0 || cpu_dfs_id == 0 {
        return 0;
    }
    // Hz arithmetic: `(CpuFid * 200_000_000) / CpuDfsId`.
    // Both bytes ≤ 255, so the multiply fits in u64 without
    // overflow.
    let hz = cpu_fid.saturating_mul(200_000_000) / cpu_dfs_id;
    // Sanity-check: real Zen2/3/4 chips fall in 1.5 GHz (mobile
    // low-power) ... 6 GHz (top-bin desktop). Anything outside
    // that range means the MSR layout we decoded doesn't apply
    // to this particular silicon (firmware-locked / virtualised
    // / future family). Return 0 so `calibrate_clocks` falls
    // through to HPET cross-check rather than installing a
    // wildly-wrong `cycles_per_ns`. A wrong cpns turns every
    // `Deadline::after_ms` into either far-future cycles (waits
    // appear stuck) or near-instant cycles (timeouts fire early).
    if !(1_000_000_000..=6_500_000_000).contains(&hz) {
        return 0;
    }
    hz
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
    if cur != 0 {
        return cur;
    }
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
    if hz != 0 {
        TSC_HZ.store(hz, Ordering::Release);
    }
}

/// Last cached TSC frequency in Hz. 0 means uncalibrated.
pub fn frequency_hz() -> u64 {
    TSC_HZ.load(Ordering::Acquire)
}

/// Convert TSC ticks to nanoseconds. 0 if uncalibrated.
pub fn ticks_to_nanos(ticks: u64) -> u64 {
    let hz = frequency_hz();
    if hz == 0 {
        return 0;
    }
    // ns = ticks * 1e9 / hz; widen to u128 to avoid overflow.
    ((ticks as u128) * 1_000_000_000 / hz as u128) as u64
}

#[doc(hidden)]
pub fn __reset_for_test() {
    TSC_HZ.store(0, Ordering::Release);
}
