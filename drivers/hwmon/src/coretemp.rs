//! Intel CPU per-core temperature driver — clean-room implementation.
//!
//! Reference: `linux/drivers/hwmon/coretemp.c` (Rudolf Marek,
//! Juerg Haefliger, Eduardo Habkost — GPL-2.0).
//!
//! ## Hardware access
//!
//! Two per-logical-CPU MSRs:
//!
//! - `IA32_THERM_STATUS` (0x19C): bit 31 = valid flag, bits 22:16 =
//!   Digital Readout (°C below Tjmax). Field is unsigned; subtract
//!   from Tjmax to get current temperature.
//!
//! - `MSR_TEMPERATURE_TARGET` (0x1A2): bits 23:16 = Tj_MAX (°C),
//!   the maximum junction temperature for this specific die. Typical
//!   values 95–105 °C. Linux coretemp.c reads this once at probe.
//!
//! Result: `temp_C = Tjmax - readout_C`.
//!
//! Exposed labels: `"Package id 0"` (package-level, reads MSR on
//! logical CPU 0) and `"Core 0"` … `"Core N-1"` for each physical
//! core. For now we expose only package-level (`"Tpackage"`) and up
//! to four cores (`"Core0"` … `"Core3"`) because NARF doesn't yet
//! have a `smp_call_function` primitive to read per-core MSRs.
//!
//! Linux coretemp.c lines referenced: `get_tjmax` (~L318),
//! `coretemp_read` (~L406), `msr_pcore_temp_read` (~L381).

extern crate alloc;

use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use crate::registry;

// ── MSR numbers ───────────────────────────────────────────────────────

/// IA32_THERM_STATUS — per-core thermal status.
/// Bit 31: valid. Bits 22:16: digital readout (units °C below Tjmax).
pub const MSR_IA32_THERM_STATUS: u32 = 0x19C;

/// MSR_TEMPERATURE_TARGET — target junction temperature.
/// Bits 23:16: Tj_MAX (°C). Model-dependent; reads must recover from #GP.
pub const MSR_TEMPERATURE_TARGET: u32 = 0x1A2;

/// Intel's digital thermal sensor is enumerated by CPUID.06H:EAX[0].
/// Neither generic MSR support nor the legacy ACPI feature implies it.
#[cfg(target_arch = "x86_64")]
pub(crate) fn supports_coretemp(
    vendor: narf_arch::x86_64::microcode::Vendor,
    max_basic: u32,
    thermal_eax: u32,
) -> bool {
    vendor == narf_arch::x86_64::microcode::Vendor::Intel && max_basic >= 6 && thermal_eax & 1 != 0
}

/// The driver probe and runtime reads share the same admission gate. CPUID
/// thermal features alone do not guarantee that a model-specific MSR is
/// readable, so the final operation is also fallible.
#[cfg(any(target_arch = "x86_64", feature = "kernel-test"))]
fn read_supported_msr(
    index: u32,
    mut cpuid: impl FnMut(u32) -> (u32, u32, u32, u32),
    mut read: impl FnMut(u32) -> Option<u64>,
) -> Option<u64> {
    let (max, ebx, ecx, edx) = cpuid(0);
    if max < 6
        || ebx != u32::from_le_bytes(*b"Genu")
        || edx != u32::from_le_bytes(*b"ineI")
        || ecx != u32::from_le_bytes(*b"ntel")
    {
        return None;
    }
    if cpuid(1).3 & (1 << 5) == 0 {
        return None;
    }
    let thermal_eax = cpuid(6).0;
    #[cfg(target_arch = "x86_64")]
    let thermal = supports_coretemp(
        narf_arch::x86_64::microcode::Vendor::Intel,
        max,
        thermal_eax,
    );
    #[cfg(not(target_arch = "x86_64"))]
    let thermal = thermal_eax & 1 != 0;
    if !thermal {
        return None;
    }
    read(index)
}

#[cfg(target_arch = "x86_64")]
fn read_thermal_msr(index: u32) -> Option<u64> {
    // Keep this CPU pinned and prevent an IRQ path from overwriting its
    // recoverable-probe state while an optional MSR access is armed.
    narf_lib::sync::without_interrupts(|| {
        read_supported_msr(
            index,
            // SAFETY: CPUID is available on x86_64; the admission gate checks
            // the maximum basic leaf before querying leaves 1 and 6.
            |leaf| unsafe { narf_arch::x86_64::cpuid::cpuid(leaf, 0) },
            |index| narf_arch::x86_64::msr::rdmsr_or_gp(index).ok(),
        )
    })
}

// ── Decode helpers ────────────────────────────────────────────────────

/// Decode the digital readout from `IA32_THERM_STATUS`.
///
/// Returns `None` if the status register's valid bit (31) is clear.
/// Result is °C below Tjmax; subtract from Tjmax to get current temp.
///
/// Linux coretemp.c `msr_pcore_temp_read` ~L381.
#[inline]
pub fn decode_therm_status(msr_val: u64) -> Option<u32> {
    if msr_val & (1 << 31) == 0 {
        return None; // valid bit clear — reading not stable
    }
    // Bits 22:16 of the lower 32 bits.
    let readout = ((msr_val as u32) >> 16) & 0x7F;
    Some(readout)
}

/// Decode Tjmax from `MSR_TEMPERATURE_TARGET`.
///
/// Bits 23:16 give the package Tjmax in degrees Celsius.
/// Linux coretemp.c `get_tjmax` ~L318.
#[inline]
pub fn decode_tjmax(msr_val: u64) -> u32 {
    ((msr_val >> 16) & 0xFF) as u32
}

/// Compute current temperature in millidegrees Celsius.
///
/// `tjmax_c` — read from MSR_TEMPERATURE_TARGET bits 23:16.
/// `readout_c` — from IA32_THERM_STATUS bits 22:16.
#[inline]
pub fn therm_to_mc(tjmax_c: u32, readout_c: u32) -> i32 {
    let cur_c = tjmax_c.saturating_sub(readout_c) as i32;
    cur_c * 1000
}

// ── Label constants ───────────────────────────────────────────────────

pub const LABELS: &[&str] = &["Tpackage", "Core0", "Core1", "Core2", "Core3"];

// ── coretemp device ───────────────────────────────────────────────────

/// Bound coretemp device. Caches Tjmax discovered at probe time.
#[derive(Debug)]
pub struct Coretemp {
    /// Tjmax in degrees Celsius as read from MSR_TEMPERATURE_TARGET.
    pub tjmax_c: u32,
    /// Logical CPU index on which MSR reads run.
    pub cpu_id: u32,
}

impl Coretemp {
    pub fn new(tjmax_c: u32, cpu_id: u32) -> Self {
        Self { tjmax_c, cpu_id }
    }

    /// Read IA32_THERM_STATUS MSR on the bound CPU.
    ///
    /// Returns `None` on unsupported CPUs or an unreadable MSR. Admission
    /// is checked on the executing CPU even for manually constructed devices.
    #[cfg(target_arch = "x86_64")]
    pub fn read_therm_status(&self) -> Option<u64> {
        read_thermal_msr(MSR_IA32_THERM_STATUS)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn read_therm_status(&self) -> Option<u64> {
        None
    }
}

impl crate::HwmonDevice for Coretemp {
    fn name(&self) -> &str {
        "coretemp"
    }

    fn read_temp(&self, label: &str) -> Option<i32> {
        match label {
            "Tpackage" | "Core0" | "Core1" | "Core2" | "Core3" => {
                let msr_val = self.read_therm_status()?;
                let readout = decode_therm_status(msr_val)?;
                Some(therm_to_mc(self.tjmax_c, readout))
            }
            _ => None,
        }
    }

    fn read_fan(&self, _label: &str) -> Option<u32> {
        None
    }

    fn read_voltage(&self, _label: &str) -> Option<i32> {
        None
    }

    fn set_fan(&self, _label: &str, _level: u8) -> bool {
        false
    }

    fn temp_limits(&self, label: &str) -> (Option<i32>, Option<i32>) {
        // Tjmax, decoded from MSR_TEMPERATURE_TARGET at probe, is the
        // junction critical limit by definition — Linux coretemp
        // publishes it as temp_crit and exposes no separate temp_max.
        match label {
            "Tpackage" | "Core0" | "Core1" | "Core2" | "Core3" => {
                (None, Some((self.tjmax_c as i32) * 1000))
            }
            _ => (None, None),
        }
    }

    fn list_labels(&self) -> Vec<&str> {
        LABELS.to_vec()
    }
}

// ── Driver registration ───────────────────────────────────────────────

/// Register the coretemp MSR driver. Called from Stage::Subsys.
/// Probe only an Intel CPU advertising MSRs and digital thermal sensors.
/// An unreadable temperature-target MSR or implausible Tjmax skips registration.
/// Returns `NotPresent` for a skipped probe and `Ok` after registration.
#[cfg(target_arch = "x86_64")]
pub fn register_msr_driver() -> narf_init::InitResult {
    use core::fmt::Write as _;
    let Some(raw) = read_thermal_msr(MSR_TEMPERATURE_TARGET) else {
        let _ = writeln!(
            narf_console::Writer,
            "  coretemp: unsupported CPU or unavailable thermal MSR, skipping"
        );
        return narf_init::InitResult::NotPresent;
    };
    let tjmax = decode_tjmax(raw);
    if !(75..=125).contains(&tjmax) {
        let _ = writeln!(
            narf_console::Writer,
            "  coretemp: Tjmax={} out of range [75,125], skipping",
            tjmax
        );
        return narf_init::InitResult::NotPresent;
    }
    let _ = writeln!(
        narf_console::Writer,
        "  coretemp: Intel CPU Tjmax={}°C",
        tjmax
    );
    registry::register(registry::RegisteredSensor {
        name: "coretemp",
        description: "Intel CPU core temperature",
        bus_loc: "msr",
    });
    use alloc::sync::Arc;
    registry::register_device(Arc::new(Coretemp::new(tjmax, 0)));
    narf_init::InitResult::Ok
}

#[cfg(not(target_arch = "x86_64"))]
pub fn register_msr_driver() -> narf_init::InitResult {
    narf_init::InitResult::NotPresent
}

#[cfg(feature = "kernel-test")]
#[path = "coretemp_tests.rs"]
mod probe_tests;
