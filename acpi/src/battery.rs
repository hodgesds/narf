//! ACPI Smart Battery — state model + _BIF / _BST decoders.
//!
//! Per ACPI 6.5 §10.2.2 every Control Method battery exposes
//! two essential methods:
//!
//! - **`_BIF`** (Battery Information): static parameters that
//!   don't change during operation — design capacity, last-full
//!   capacity, voltage, model number / serial / OEM / type.
//!   Returns a 13-element Package.
//!
//! - **`_BST`** (Battery Status): dynamic state polled every few
//!   seconds — present state (charging / discharging / critical),
//!   present rate (mA or mW), remaining capacity, present voltage.
//!   Returns a 4-element Package.
//!
//! Both methods typically call into the Embedded Controller via
//! AML `OperationRegion(EC, EmbeddedControl, ...)` field reads;
//! the AML interpreter handles that wire-up. This module owns
//! the pure decoders that turn the returned Packages into
//! strongly-typed values + a fused `BatteryState` snapshot the
//! UI / power subsystem can render.
//!
//! Reference: ACPI 6.5 §10.2.2 (Control Method Battery Devices)
//! + Linux `drivers/acpi/battery.c`.

extern crate alloc;

use alloc::string::String;

// ── Static info (_BIF return Package) ──────────────────────────────

/// Power-unit field in _BIF[0]:
///   0 → mW (capacity in mWh, rate in mW)
///   1 → mA (capacity in mAh, rate in mA)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PowerUnit {
    MilliWatt,
    MilliAmp,
}

/// Battery technology field in _BIF[10]:
///   0 → Primary (single-use)
///   1 → Secondary (rechargeable — the laptop case)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BatteryTech {
    Primary,
    Secondary,
}

/// Decoded battery info (static).
#[derive(Clone, Debug)]
pub struct BatteryInfo {
    pub power_unit: PowerUnit,
    /// Design capacity in `power_unit` × mAh (or mWh). 0xFFFFFFFF
    /// means "unknown" per spec.
    pub design_capacity: u32,
    /// Last-full-charge capacity — drifts down as the battery ages.
    pub last_full_capacity: u32,
    pub technology: BatteryTech,
    /// Design voltage in mV. 0xFFFFFFFF = unknown.
    pub design_voltage_mv: u32,
    /// Capacity warning threshold (in `power_unit` units).
    pub design_capacity_warning: u32,
    /// Capacity low threshold.
    pub design_capacity_low: u32,
    pub model_number: String,
    pub serial_number: String,
    pub battery_type: String,
    pub oem_info: String,
}

// ── Dynamic state (_BST return Package) ────────────────────────────

/// `_BST[0]` battery state bitfield. Wraps a `u32` of ACPI-spec
/// flag bits; helpers below avoid pulling in a bitflags crate dep.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BatteryStatus(pub u32);

impl BatteryStatus {
    /// Discharging (mutually exclusive with CHARGING per ACPI).
    pub const DISCHARGING: u32 = 1 << 0;
    /// Charging.
    pub const CHARGING: u32 = 1 << 1;
    /// Critical low (capacity below `_BIF.design_capacity_low`).
    pub const CRITICAL: u32 = 1 << 2;
    /// Capacity charging (platform-supported per ACPI 4.0a).
    pub const CHARGE_LIMIT: u32 = 1 << 3;

    /// True iff any of `bits` are set.
    pub fn contains(self, bits: u32) -> bool {
        self.0 & bits != 0
    }
}

/// Decoded battery state (dynamic, polled periodically).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BatteryState {
    pub status: BatteryStatus,
    /// Present discharge / charge rate in mA or mW (per
    /// [`BatteryInfo::power_unit`]). 0xFFFFFFFF = unknown.
    pub present_rate: u32,
    /// Remaining capacity in the same unit as `present_rate`.
    pub remaining_capacity: u32,
    /// Present voltage in mV.
    pub present_voltage_mv: u32,
}

impl BatteryState {
    /// Percent of `last_full_capacity` remaining, 0–100. Returns
    /// `None` when either value is "unknown" (0xFFFFFFFF) or
    /// `last_full_capacity` is zero (would divide-by-zero).
    pub fn percent_remaining(&self, info: &BatteryInfo) -> Option<u8> {
        if self.remaining_capacity == 0xFFFF_FFFF
            || info.last_full_capacity == 0
            || info.last_full_capacity == 0xFFFF_FFFF
        {
            return None;
        }
        let pct = (self.remaining_capacity as u64 * 100) / info.last_full_capacity as u64;
        Some(pct.min(100) as u8)
    }

    /// Convenience: is the battery discharging? Useful for
    /// "running on battery" UX without a separate AC adapter probe.
    pub fn is_discharging(&self) -> bool {
        self.status.contains(BatteryStatus::DISCHARGING)
    }

    /// Convenience: is the battery at critical-low? Triggers
    /// the OS's "save your work" path.
    pub fn is_critical(&self) -> bool {
        self.status.contains(BatteryStatus::CRITICAL)
    }
}

// ── Decoders ───────────────────────────────────────────────────────

/// Decode error — the package didn't match the _BIF / _BST shape.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Wrong element count. _BIF expects 13, _BST expects 4.
    WrongElementCount,
    /// power_unit field had a value other than 0 or 1.
    BadPowerUnit,
    /// technology field had a value other than 0 or 1.
    BadTechnology,
}

/// Decode a _BIF return value. AML returns a 13-element Package:
/// `(power_unit, design_capacity, last_full_capacity, tech,
///   design_voltage, capacity_warning, capacity_low,
///   capacity_granularity_1, capacity_granularity_2,
///   model_number_str, serial_number_str, type_str, oem_info_str)`.
///
/// `ints` is the first 9 integer elements; `strings` is the last
/// 4 string elements. Caller's AML evaluator splits the Package.
pub fn decode_bif(ints: &[u32; 9], strings: &[String; 4]) -> Result<BatteryInfo, DecodeError> {
    let power_unit = match ints[0] {
        0 => PowerUnit::MilliWatt,
        1 => PowerUnit::MilliAmp,
        _ => return Err(DecodeError::BadPowerUnit),
    };
    let technology = match ints[3] {
        0 => BatteryTech::Primary,
        1 => BatteryTech::Secondary,
        _ => return Err(DecodeError::BadTechnology),
    };
    Ok(BatteryInfo {
        power_unit,
        design_capacity: ints[1],
        last_full_capacity: ints[2],
        technology,
        design_voltage_mv: ints[4],
        design_capacity_warning: ints[5],
        design_capacity_low: ints[6],
        // ints[7]/ints[8] = granularity_1/granularity_2 — not
        // useful for the UI surface; we drop them.
        model_number: strings[0].clone(),
        serial_number: strings[1].clone(),
        battery_type: strings[2].clone(),
        oem_info: strings[3].clone(),
    })
}

/// Decode a _BST return value. AML returns a 4-element Package:
/// `(battery_state, present_rate, remaining_capacity, present_voltage)`.
pub fn decode_bst(values: &[u32; 4]) -> Result<BatteryState, DecodeError> {
    Ok(BatteryState {
        status: BatteryStatus(values[0]),
        present_rate: values[1],
        remaining_capacity: values[2],
        present_voltage_mv: values[3],
    })
}
