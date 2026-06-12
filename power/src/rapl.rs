//! RAPL (Running Average Power Limit) energy telemetry.
//!
//! Spec: `power/specification/cpu-power.md` §3. Reads the
//! per-domain energy counters into integer microjoules. The
//! counters are 32-bit and wrap; consumers take a delta.
//!
//! Also wraps the related thermal MSRs (`THERM_STATUS`,
//! `PACKAGE_THERM_STATUS`, `TEMPERATURE_TARGET`) since they're
//! the natural cousin telemetry surface.

#![allow(dead_code)]

use narf_arch::x86_64::cpuid::cpuid;
use narf_arch::x86_64::msr::rdmsr;

// ── MSR map ────────────────────────────────────────────────────────

pub const MSR_RAPL_POWER_UNIT: u32 = 0x606;
pub const MSR_PKG_ENERGY_STATUS: u32 = 0x611;
pub const MSR_PP0_ENERGY_STATUS: u32 = 0x639;
pub const MSR_PP1_ENERGY_STATUS: u32 = 0x641;
pub const MSR_DRAM_ENERGY_STATUS: u32 = 0x619;
pub const MSR_PKG_POWER_INFO: u32 = 0x614;

pub const MSR_IA32_THERM_STATUS: u32 = 0x19C;
pub const MSR_IA32_PACKAGE_THERM_STATUS: u32 = 0x1B1;
pub const MSR_TEMPERATURE_TARGET: u32 = 0x1A2;

/// Decoded `MSR_RAPL_POWER_UNIT` — converted to integer
/// micro-units. e.g. `energy_uj_per_unit = 10^6 / 2^energy_units`.
#[derive(Copy, Clone, Debug, Default)]
pub struct EnergyUnits {
    pub power_uw_per_unit: u64,
    pub energy_uj_per_unit: u64,
    pub time_us_per_unit: u64,
    /// Raw `energy_units` exponent — handy for the
    /// `(raw * 1_000_000) >> exp` direct conversion path.
    pub energy_exp: u8,
}

/// `true` iff RAPL is reported by the host.
///
/// Intel: CPUID(6).EAX[14] hints at thermal/RAPL — but the
/// definitive test is reading `MSR_RAPL_POWER_UNIT` returning a
/// non-zero, sane value. AMD: same MSR exists since Family 17h.
/// Stage cut: just probe the MSR itself.
pub fn is_supported() -> bool {
    // Quick CPUID-based bail for hosts that explicitly don't
    // advertise it; otherwise trust the MSR probe.
    // SAFETY: leaf 6 only defined when CPUID max >= 6.
    let (max, _, _, _) = unsafe { cpuid(0, 0) };
    if max >= 6 {
        // Fall through to the MSR probe — Intel CPUID(6).EAX[14]
        // covers thermal but RAPL itself isn't always advertised
        // there.
    }
    // SAFETY: rdmsr at CPL=0; if the MSR is missing we'd #GP, so
    // wrap behind the `is_supported` indirection that callers gate
    // on.
    // SAFETY: Valid memory or trusted environment
    let raw = unsafe { rdmsr(MSR_RAPL_POWER_UNIT) };
    raw != 0 && raw != u64::MAX
}

/// Decode `MSR_RAPL_POWER_UNIT`.
///
/// # Safety
/// CPL = 0; `is_supported()` is true.
pub unsafe fn units() -> EnergyUnits {
    // SAFETY: caller-asserted.
    let raw = unsafe { rdmsr(MSR_RAPL_POWER_UNIT) };
    let power_exp = (raw & 0x0F) as u32;
    let energy_exp = ((raw >> 8) & 0x1F) as u32;
    let time_exp = ((raw >> 16) & 0x0F) as u32;
    EnergyUnits {
        // Watts = 1 / 2^power_exp; in µW = 10^6 / 2^p.
        power_uw_per_unit: if power_exp < 32 {
            1_000_000u64 >> power_exp
        } else {
            0
        },
        energy_uj_per_unit: if energy_exp < 32 {
            1_000_000u64 >> energy_exp
        } else {
            0
        },
        time_us_per_unit: if time_exp < 32 {
            1_000_000u64 >> time_exp
        } else {
            0
        },
        energy_exp: energy_exp as u8,
    }
}

/// Read a 32-bit RAPL energy-status counter and scale it to µJ.
///
/// # Safety
/// CPL = 0 and `is_supported()` is true (so both `msr` and
/// `MSR_RAPL_POWER_UNIT` are implemented on this CPU).
unsafe fn read_energy_uj(msr: u32) -> u64 {
    // SAFETY: the caller guarantees CPL=0 and that `msr` is an
    // implemented RAPL energy-status MSR; mask to its low 32 bits.
    // SAFETY: Valid memory or trusted environment
    let raw32 = unsafe { rdmsr(msr) } & 0xFFFF_FFFF;
    // SAFETY: the caller guarantees CPL=0 and is_supported(), which is
    // exactly `units()`'s contract.
    // SAFETY: Valid memory or trusted environment
    let u = unsafe { units() };
    raw32.saturating_mul(u.energy_uj_per_unit)
}

/// Package energy in microjoules. Rolls over (32-bit counter ×
/// `energy_uj_per_unit`); take a delta.
///
/// # Safety
/// CPL = 0; RAPL supported.
pub unsafe fn read_pkg_uj() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { read_energy_uj(MSR_PKG_ENERGY_STATUS) }
}

/// PP0 (cores) energy in microjoules.
///
/// # Safety
/// Same as `read_pkg_uj`.
pub unsafe fn read_pp0_uj() -> u64 {
    // SAFETY: caller-asserted.
    unsafe { read_energy_uj(MSR_PP0_ENERGY_STATUS) }
}

/// PP1 (uncore / iGPU) energy in microjoules. `None` if MSR
/// isn't populated (server SKUs).
///
/// # Safety
/// CPL = 0.
pub unsafe fn read_pp1_uj() -> Option<u64> {
    // SAFETY: caller-asserted.
    let raw = unsafe { rdmsr(MSR_PP1_ENERGY_STATUS) };
    if raw == 0 || raw == u64::MAX {
        return None;
    }
    // SAFETY: same.
    Some(unsafe { read_energy_uj(MSR_PP1_ENERGY_STATUS) })
}

/// DRAM energy in microjoules. `None` if MSR isn't populated
/// (client SKUs without DRAM RAPL).
///
/// # Safety
/// CPL = 0.
pub unsafe fn read_dram_uj() -> Option<u64> {
    // SAFETY: caller-asserted.
    let raw = unsafe { rdmsr(MSR_DRAM_ENERGY_STATUS) };
    if raw == 0 || raw == u64::MAX {
        return None;
    }
    // SAFETY: same.
    Some(unsafe { read_energy_uj(MSR_DRAM_ENERGY_STATUS) })
}

// ── Thermal ────────────────────────────────────────────────────────

/// Read the per-CPU thermal status. The "digital readout" field
/// at bits[22:16] is the offset in °C below TjMax.
///
/// Returns `None` if `THERM_STATUS.bit 31` (Reading-Valid) isn't
/// set — i.e. the digital sensor hasn't completed its first
/// conversion yet.
///
/// # Safety
/// CPL = 0.
pub unsafe fn read_temp_c() -> Option<u8> {
    // SAFETY: caller-asserted.
    let s = unsafe { rdmsr(MSR_IA32_THERM_STATUS) };
    if s & (1 << 31) == 0 {
        return None;
    }
    let offset = ((s >> 16) & 0x7F) as u8;
    // SAFETY: same.
    let tj = unsafe { rdmsr(MSR_TEMPERATURE_TARGET) };
    let tjmax = ((tj >> 16) & 0xFF) as u8;
    if tjmax == 0 {
        return None;
    }
    Some(tjmax.saturating_sub(offset))
}

/// Read the package thermal status. Same decode as
/// `read_temp_c`.
///
/// # Safety
/// CPL = 0; the package thermal MSR exists (Sandy Bridge+).
pub unsafe fn read_pkg_temp_c() -> Option<u8> {
    // SAFETY: caller-asserted.
    let s = unsafe { rdmsr(MSR_IA32_PACKAGE_THERM_STATUS) };
    if s & (1 << 31) == 0 {
        return None;
    }
    let offset = ((s >> 16) & 0x7F) as u8;
    // SAFETY: same.
    let tj = unsafe { rdmsr(MSR_TEMPERATURE_TARGET) };
    let tjmax = ((tj >> 16) & 0xFF) as u8;
    if tjmax == 0 {
        return None;
    }
    Some(tjmax.saturating_sub(offset))
}
