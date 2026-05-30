//! ACPI Control Method Battery (`PNP0C0A`) — typed `_BIX` + `_BST` view.
//!
//! Spec: ACPI 6.5 §10.2 Control Method Batteries.
//!   <https://uefi.org/specs/ACPI/>
//!
//! Adapted from `drivers/acpi/battery.c` (Linux, GPL-2.0-or-later).
//! NARF is GPL-2.0-or-later since 2026-05-20, so direct adaptation is
//! permitted; field naming follows the ACPI 6.5 spec, not Linux's
//! shorter-but-cryptic internal names.
//!
//! This module is the typed, ACPI-spec-aligned view of one or more
//! batteries. The legacy `drivers/platform/src/battery.rs` wraps the
//! same `_BST` polling logic into a `PowerSource` trait object for
//! `power::list_sources`; this one returns a `BatteryDevice` with
//! `info()` / `status()` accessors that decode the full `_BIX` /
//! `_BST` package shape — `power_unit`, `cycle_count`,
//! `design_voltage`, all of it.
//!
//! # Hard rules
//! - **No `_BIF` fallback.** `_BIX` (ACPI 4.0+, §10.2.2.2) is the
//!   modern shape; firmware shipping on a Zen2 / Phoenix laptop
//!   from 2020 onward always exposes it. If a board only ships
//!   `_BIF`, the call returns `BatteryError::MethodMissing`. Hard
//!   cutover per MEMORY.md.
//! - **EC degrades gracefully.** Some platforms put battery telemetry
//!   in EC space; if the sibling `narf_aml::ec` module isn't ready,
//!   `status()` may surface `MethodMissing` until the EC opregion
//!   is wired in. Tests don't depend on the live EC.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use narf_aml::eval::evaluate_method;
use narf_aml::{find_all_devices_by_hid, Value};
use narf_lib::sync::IrqSafeSpinLock;

// ── Notify fan-out ─────────────────────────────────────────────────

/// Battery notification events. Values mirror the ACPI notify codes.
///
/// Spec: ACPI 6.5 §10.2 — Notify(battery, 0x80) = "battery status
/// changed" (new `_BST`), Notify(battery, 0x81) = "battery info
/// changed" (new `_BIX`). The `_BTP` trip-point fires its own 0x80
/// but in a distinct context tracked by `CapacityLow`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BatteryTripEvent {
    /// Notify code 0x80: battery status changed (new `_BST` available).
    StatusChanged,
    /// Notify code 0x81: battery info changed (new `_BIX`; e.g. new
    /// battery inserted or design-capacity recalibrated).
    InfoChanged,
    /// `_BTP` trip point crossed — remaining capacity dropped below
    /// the programmed threshold.
    CapacityLow,
}

type BatterySubscriber = Box<dyn Fn(&BatteryTripEvent) + Send + Sync + 'static>;

static BATTERY_SUBS: IrqSafeSpinLock<Vec<BatterySubscriber>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register a callback for battery trip events. Called from the
/// ACPI notify dispatcher (0x80/0x81) and from `_BTP` expiry.
///
/// All registered callbacks run synchronously on the notify/SCI thread
/// — keep them short and non-blocking.
pub fn subscribe<F>(cb: F)
where
    F: Fn(&BatteryTripEvent) + Send + Sync + 'static,
{
    BATTERY_SUBS.lock().push(Box::new(cb));
}

/// Number of registered battery subscribers (debug helper).
pub fn subscriber_count() -> usize {
    BATTERY_SUBS.lock().len()
}

/// Fan out a raw ACPI Notify code to all registered subscribers.
/// 0x80 → `StatusChanged`, 0x81 → `InfoChanged`, other → `CapacityLow`.
pub fn notify(code: u8) {
    let ev = match code {
        0x80 => BatteryTripEvent::StatusChanged,
        0x81 => BatteryTripEvent::InfoChanged,
        _ => BatteryTripEvent::CapacityLow,
    };
    let subs = BATTERY_SUBS.lock();
    for cb in subs.iter() {
        cb(&ev);
    }
}

/// Convenience: directly signal a capacity-low trip (from `_BTP`
/// polling logic or firmware event).
pub fn notify_capacity_low() {
    let ev = BatteryTripEvent::CapacityLow;
    let subs = BATTERY_SUBS.lock();
    for cb in subs.iter() {
        cb(&ev);
    }
}

/// Reset subscribers — test helper only.
#[doc(hidden)]
pub fn __reset_for_test() {
    BATTERY_SUBS.lock().clear();
}

/// One PNP0C0A battery device. Cheap to clone (just a path string).
#[derive(Clone, Debug)]
pub struct BatteryDevice {
    /// Fully-qualified namespace path, e.g. `"\\_SB.PCI0.LPCB.EC0.BAT0"`.
    /// `_BIX` / `_BST` are evaluated against `<path>._BIX` /
    /// `<path>._BST`.
    pub path: String,
}

/// `_BIX` (Battery Information Extended) decoded fields.
///
/// Spec: ACPI 6.5 §10.2.2.2. The package layout is documented as 21
/// entries; this struct exposes the ones drivers and userspace
/// actually consume. Fields whose interpretation depends on
/// `power_unit` (mA-vs-mW vs mAh-vs-mWh) are not unit-converted here
/// — the caller decides. `mAh` / `mA` when `power_unit == 1`,
/// `mWh` / `mW` when `power_unit == 0`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatteryInfo {
    /// Revision (field 0). ACPI 6.5 mandates revision 0; future
    /// revisions append fields — readers should tolerate longer
    /// packages and ignore extras.
    pub revision: u64,
    /// Field 1: 0 = mW / mWh (default), 1 = mA / mAh.
    pub power_unit: u64,
    /// Field 2: design capacity. Unit per `power_unit`.
    pub design_capacity: u64,
    /// Field 3: last full charge capacity. Drops over the battery's
    /// life as the cell wears out.
    pub last_full_charge: u64,
    /// Field 4: battery technology — 0 = primary (non-rechargeable),
    /// 1 = secondary (rechargeable). Laptops always = 1.
    pub technology: u64,
    /// Field 5: design voltage in mV.
    pub design_voltage: u64,
    /// Field 6: design capacity of warning. Threshold below which the
    /// OS should warn the user.
    pub design_capacity_warning: u64,
    /// Field 7: design capacity of low. Threshold below which the
    /// OS should suspend or shut down.
    pub design_capacity_low: u64,
    /// Field 8: cycle count. 0xFFFF_FFFF = unknown.
    pub cycle_count: u64,
    /// Field 9: measurement accuracy in thousandths of a percent
    /// (e.g. 80000 = 80.000% confidence). Most firmware reports
    /// 80000 or leaves it unknown.
    pub measurement_accuracy: u64,
    /// Field 10: max sampling time in ms (worst-case `_BST` latency).
    pub max_sampling_time_ms: u64,
    /// Field 11: min sampling time in ms.
    pub min_sampling_time_ms: u64,
    /// Field 12: max averaging interval in ms.
    pub max_averaging_interval_ms: u64,
    /// Field 13: min averaging interval in ms.
    pub min_averaging_interval_ms: u64,
    /// Field 14: capacity granularity 1 (warning..low band).
    pub capacity_granularity_1: u64,
    /// Field 15: capacity granularity 2 (low..full band).
    pub capacity_granularity_2: u64,
    /// Field 16: model number (string).
    pub model_number: String,
    /// Field 17: serial number (string).
    pub serial_number: String,
    /// Field 18: battery type (chemistry, e.g. `"LIon"`).
    pub battery_type: String,
    /// Field 19: OEM info (string).
    pub oem_info: String,
}

/// `_BST` field 0: Battery State bits per ACPI 6.5 §10.2.2.6.
/// `discharging | charging` is mutually exclusive (per spec), but
/// some firmware mis-reports both during a transition — callers
/// MUST tolerate that and prefer `charging` over `discharging`.
///
/// Hand-rolled rather than via `bitflags!` because the workspace
/// doesn't pull `bitflags` and one tiny u8 isn't worth a new crate
/// dep.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BatteryStateBits(pub u8);

impl BatteryStateBits {
    /// Bit 0: battery is currently discharging into the system.
    pub const DISCHARGING: BatteryStateBits = BatteryStateBits(1 << 0);
    /// Bit 1: battery is currently being charged.
    pub const CHARGING: BatteryStateBits = BatteryStateBits(1 << 1);
    /// Bit 2: battery is in a critically low state — the firmware is
    /// signalling the OS to suspend or shut down.
    pub const CRITICAL: BatteryStateBits = BatteryStateBits(1 << 2);

    /// Mask of bits we model. ACPI 6.5 reserves bit 3..7; truncate so
    /// buggy firmware that scribbles in the upper bits doesn't leak
    /// into our state.
    pub const KNOWN_MASK: u8 = 0b111;

    /// Construct from raw `_BST` field 0, masking off reserved bits.
    #[inline]
    pub const fn from_bits_truncate(raw: u64) -> Self {
        BatteryStateBits((raw as u8) & Self::KNOWN_MASK)
    }

    /// Bitwise AND check.
    #[inline]
    pub const fn contains(self, other: BatteryStateBits) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// `_BST` (Battery Status) decoded fields. Spec: ACPI 6.5 §10.2.2.6.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BatteryStatus {
    /// State bits — see [`BatteryStateBits`].
    pub state: BatteryStateBits,
    /// Present rate. Unit per `_BIX.power_unit`: mA (`power_unit ==
    /// 1`) or mW (`power_unit == 0`). 0xFFFF_FFFF = unknown.
    pub present_rate: u64,
    /// Remaining capacity. Unit per `_BIX.power_unit`: mAh or mWh.
    pub remaining_capacity: u64,
    /// Present voltage in mV. 0xFFFF_FFFF = unknown.
    pub present_voltage: u64,
}

/// Errors from `_BIX` / `_BST` evaluation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BatteryError {
    /// `_BIX` or `_BST` returned something other than `Package`.
    NotAPackage,
    /// Package is too short for the field we're decoding.
    PackageTooShort,
    /// Method is missing from the namespace (e.g. firmware only
    /// exposes `_BIF` and we don't fall back). Hard cutover.
    MethodMissing,
}

impl BatteryDevice {
    /// Evaluate `<path>._BIX` and decode the package. Returns
    /// `MethodMissing` if the namespace has no `_BIX` for this
    /// device — we deliberately do NOT fall back to `_BIF`.
    pub fn info(&self) -> Result<BatteryInfo, BatteryError> {
        let mut method = self.path.clone();
        method.push_str("._BIX");
        let v = evaluate_method(&method, &[]).map_err(|_| BatteryError::MethodMissing)?;
        decode_bix(&v)
    }

    /// Evaluate `<path>._BST` and decode the 4-tuple.
    pub fn status(&self) -> Result<BatteryStatus, BatteryError> {
        let mut method = self.path.clone();
        method.push_str("._BST");
        let v = evaluate_method(&method, &[]).map_err(|_| BatteryError::MethodMissing)?;
        decode_bst(&v)
    }

    /// Set the `_BTP` (Battery Trip Point) to `capacity`. Firmware fires
    /// Notify(battery, 0x80) when `remaining_capacity` crosses this value.
    ///
    /// Spec: ACPI 6.5 §10.2.2.7 `_BTP(TripPoint)`. Pass 0 to disable the
    /// trip point. The argument is in the same unit as `_BST.remaining_capacity`
    /// (mAh or mWh depending on `_BIX.power_unit`). Returns `MethodMissing`
    /// on firmware that doesn't implement `_BTP` (desktops; some embedded
    /// platforms).
    pub fn set_trip(&self, capacity: u64) -> Result<(), BatteryError> {
        let mut method = self.path.clone();
        method.push_str("._BTP");
        evaluate_method(&method, &[Value::Integer(capacity)])
            .map(|_| ())
            .map_err(|_| BatteryError::MethodMissing)
    }
}

/// Enumerate every PNP0C0A device in the AML namespace. Empty on
/// platforms with no batteries (desktop, VM).
pub fn enumerate() -> Vec<BatteryDevice> {
    find_all_devices_by_hid("PNP0C0A")
        .into_iter()
        .map(|n| BatteryDevice { path: n.path })
        .collect()
}

/// Decode a `_BIX` return Value. Public so tests can exercise the
/// decode against a synthetic package without touching the live
/// AML namespace.
pub fn decode_bix(v: &Value) -> Result<BatteryInfo, BatteryError> {
    let pkg = match v {
        Value::Package(p) => p,
        _ => return Err(BatteryError::NotAPackage),
    };
    // _BIX revision 0 has 20 fields (indices 0..=19). Some firmware
    // ships extra trailing fields; ignore them.
    if pkg.len() < 20 {
        return Err(BatteryError::PackageTooShort);
    }
    let s = |idx: usize| -> String {
        match &pkg[idx] {
            Value::String(s) => s.clone(),
            Value::Buffer(b) => {
                // Some firmware encodes the string fields as raw
                // null-terminated buffers. Drop the trailing NUL and
                // anything past it; treat invalid UTF-8 as empty.
                let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                core::str::from_utf8(&b[..end])
                    .map(String::from)
                    .unwrap_or_default()
            }
            _ => String::new(),
        }
    };
    Ok(BatteryInfo {
        revision: pkg[0].as_integer(),
        power_unit: pkg[1].as_integer(),
        design_capacity: pkg[2].as_integer(),
        last_full_charge: pkg[3].as_integer(),
        technology: pkg[4].as_integer(),
        design_voltage: pkg[5].as_integer(),
        design_capacity_warning: pkg[6].as_integer(),
        design_capacity_low: pkg[7].as_integer(),
        cycle_count: pkg[8].as_integer(),
        measurement_accuracy: pkg[9].as_integer(),
        max_sampling_time_ms: pkg[10].as_integer(),
        min_sampling_time_ms: pkg[11].as_integer(),
        max_averaging_interval_ms: pkg[12].as_integer(),
        min_averaging_interval_ms: pkg[13].as_integer(),
        capacity_granularity_1: pkg[14].as_integer(),
        capacity_granularity_2: pkg[15].as_integer(),
        model_number: s(16),
        serial_number: s(17),
        battery_type: s(18),
        oem_info: s(19),
    })
}

/// Decode a `_BST` return Value. Public so the trip-point and
/// state-bit tests can drive it from a synthetic Package.
pub fn decode_bst(v: &Value) -> Result<BatteryStatus, BatteryError> {
    let pkg = match v {
        Value::Package(p) => p,
        _ => return Err(BatteryError::NotAPackage),
    };
    if pkg.len() < 4 {
        return Err(BatteryError::PackageTooShort);
    }
    let raw_state = pkg[0].as_integer();
    // Mask off bits we don't model; ACPI 6.5 reserves bits 3..63 but
    // a few buggy firmwares leak garbage there.
    let state = BatteryStateBits::from_bits_truncate(raw_state & 0b111);
    Ok(BatteryStatus {
        state,
        present_rate: pkg[1].as_integer(),
        remaining_capacity: pkg[2].as_integer(),
        present_voltage: pkg[3].as_integer(),
    })
}

// ── Tests ───────────────────────────────────────────────────────────

mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_battery_bix_decode() -> TestResult {
        // Synthetic _BIX package representing a typical Li-ion laptop
        // battery: 50 Wh design, 47 Wh last-full, 12 V nominal,
        // 312 cycles, "BAT0/Li-ion/ACME".
        let pkg = Value::Package(vec![
            Value::Integer(0),                       // revision
            Value::Integer(0),                       // power_unit = mW/mWh
            Value::Integer(50_000),                  // design_capacity (mWh)
            Value::Integer(47_000),                  // last_full_charge
            Value::Integer(1),                       // technology = secondary
            Value::Integer(12_000),                  // design_voltage (mV)
            Value::Integer(5_000),                   // warning
            Value::Integer(2_500),                   // low
            Value::Integer(312),                     // cycle_count
            Value::Integer(80_000),                  // measurement_accuracy
            Value::Integer(60_000),                  // max_sampling_time_ms
            Value::Integer(1_000),                   // min_sampling_time_ms
            Value::Integer(60_000),                  // max_averaging_interval_ms
            Value::Integer(1_000),                   // min_averaging_interval_ms
            Value::Integer(100),                     // capacity_granularity_1
            Value::Integer(100),                     // capacity_granularity_2
            Value::String("Model-X".to_string()),    // model_number
            Value::String("SN-12345".to_string()),   // serial_number
            Value::String("LIon".to_string()),       // battery_type
            Value::String("ACME-OEM".to_string()),   // oem_info
        ]);
        let bix = match decode_bix(&pkg) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("decode_bix rejected a well-formed 20-field package"),
        };
        if bix.design_capacity != 50_000 {
            return TestResult::Fail("design_capacity mis-decoded");
        }
        if bix.last_full_charge != 47_000 {
            return TestResult::Fail("last_full_charge mis-decoded");
        }
        if bix.cycle_count != 312 {
            return TestResult::Fail("cycle_count mis-decoded");
        }
        if bix.design_voltage != 12_000 {
            return TestResult::Fail("design_voltage mis-decoded");
        }
        if bix.technology != 1 {
            return TestResult::Fail("technology mis-decoded");
        }
        if bix.battery_type != "LIon" {
            return TestResult::Fail("battery_type string mis-decoded");
        }
        if bix.model_number != "Model-X" {
            return TestResult::Fail("model_number string mis-decoded");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/battery", smoke_battery_bix_decode);

    fn smoke_battery_bst_state_bits() -> TestResult {
        // Case 1: discharging at 1 A, half full, 11.2 V.
        let pkg = Value::Package(vec![
            Value::Integer(0b001), // discharging
            Value::Integer(1_000), // present_rate
            Value::Integer(23_500),
            Value::Integer(11_200),
        ]);
        let bst = match decode_bst(&pkg) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("decode_bst rejected a well-formed 4-tuple"),
        };
        if !bst.state.contains(BatteryStateBits::DISCHARGING) {
            return TestResult::Fail("DISCHARGING bit not set");
        }
        if bst.state.contains(BatteryStateBits::CHARGING) {
            return TestResult::Fail("CHARGING bit set on discharge package");
        }
        if bst.state.contains(BatteryStateBits::CRITICAL) {
            return TestResult::Fail("CRITICAL bit set spuriously");
        }
        if bst.present_rate != 1_000
            || bst.remaining_capacity != 23_500
            || bst.present_voltage != 11_200
        {
            return TestResult::Fail("present_rate/remaining/voltage mis-decoded");
        }

        // Case 2: charging + critical (firmware glitch — both can fire
        // during a low-battery start-charge sequence). Bit-truncate
        // mask covers the noise.
        let pkg2 = Value::Package(vec![
            Value::Integer(0b110 | (0xff << 8)), // charging + critical + garbage
            Value::Integer(0xFFFF_FFFF),         // unknown rate
            Value::Integer(500),
            Value::Integer(11_500),
        ]);
        let bst2 = decode_bst(&pkg2).unwrap();
        if !bst2.state.contains(BatteryStateBits::CHARGING) {
            return TestResult::Fail("CHARGING bit not parsed from charging-critical pkg");
        }
        if !bst2.state.contains(BatteryStateBits::CRITICAL) {
            return TestResult::Fail("CRITICAL bit not parsed from charging-critical pkg");
        }
        if bst2.state.contains(BatteryStateBits::DISCHARGING) {
            return TestResult::Fail("DISCHARGING bit leaked from upper bits");
        }
        if bst2.present_rate != 0xFFFF_FFFF {
            return TestResult::Fail("0xFFFFFFFF unknown-rate sentinel mis-handled");
        }

        TestResult::Pass
    }
    kernel_test_in!("power/battery", smoke_battery_bst_state_bits);

    fn smoke_battery_decode_rejects_short_pkg() -> TestResult {
        let pkg = Value::Package(vec![Value::Integer(0), Value::Integer(0)]);
        match decode_bix(&pkg) {
            Err(BatteryError::PackageTooShort) => {}
            _ => return TestResult::Fail("decode_bix accepted a 2-field package"),
        }
        let pkg = Value::Package(vec![Value::Integer(0)]);
        match decode_bst(&pkg) {
            Err(BatteryError::PackageTooShort) => {}
            _ => return TestResult::Fail("decode_bst accepted a 1-field package"),
        }
        // Not a package at all
        match decode_bix(&Value::Integer(0)) {
            Err(BatteryError::NotAPackage) => {}
            _ => return TestResult::Fail("decode_bix accepted a non-Package value"),
        }
        TestResult::Pass
    }
    kernel_test_in!("power/battery", smoke_battery_decode_rejects_short_pkg);

    fn smoke_battery_btp_trip_notify_fanout() -> TestResult {
        use super::{
            notify, notify_capacity_low, subscribe, subscriber_count, BatteryTripEvent,
            __reset_for_test,
        };
        use alloc::sync::Arc;
        use narf_lib::sync::IrqSafeSpinLock;

        __reset_for_test();
        if subscriber_count() != 0 {
            return TestResult::Fail("fresh subscriber list must be empty");
        }

        // Use a spinlock-protected Vec to collect events from the callback.
        let events: Arc<IrqSafeSpinLock<Vec<BatteryTripEvent>>> =
            Arc::new(IrqSafeSpinLock::new(Vec::new()));
        let ev_clone = Arc::clone(&events);
        subscribe(move |e| {
            ev_clone.lock().push(*e);
        });

        if subscriber_count() != 1 {
            return TestResult::Fail("subscriber_count must be 1 after subscribe");
        }

        // Notify(0x80) → StatusChanged.
        notify(0x80);
        {
            let evs = events.lock();
            if evs.len() != 1 || evs[0] != BatteryTripEvent::StatusChanged {
                return TestResult::Fail("notify(0x80) must yield StatusChanged");
            }
        }

        // Notify(0x81) → InfoChanged.
        notify(0x81);
        {
            let evs = events.lock();
            if evs.len() != 2 || evs[1] != BatteryTripEvent::InfoChanged {
                return TestResult::Fail("notify(0x81) must yield InfoChanged");
            }
        }

        // notify_capacity_low() → CapacityLow.
        notify_capacity_low();
        {
            let evs = events.lock();
            if evs.len() != 3 || evs[2] != BatteryTripEvent::CapacityLow {
                return TestResult::Fail("notify_capacity_low must yield CapacityLow");
            }
        }

        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("power/battery", smoke_battery_btp_trip_notify_fanout);
}
