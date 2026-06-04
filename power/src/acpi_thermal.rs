//! ACPI Thermal Zones (`PNP0C0F` / `ThermalZone` namespace nodes).
//!
//! Spec: ACPI 6.5 §11 (Thermal Management).
//!   <https://uefi.org/specs/ACPI/>
//!
//! Adapted from Linux's `drivers/thermal/` (GPL-2.0-or-later) and
//! `drivers/acpi/thermal.c`. NARF is GPL-2.0-or-later since
//! 2026-05-20.
//!
//! # Layering vs `power/src/thermal.rs`
//!
//! `power::thermal` (sibling module) provides the **generic** thermal
//! registry: a generic `ThermalZone` with milli-degree-C readings,
//! subscriber callbacks, and active-cooling step policies. Drivers
//! (ACPI, intel-coretemp, k10temp, ...) all feed into it.
//!
//! This module is the **ACPI-specific** view: walking
//! `NodeKind::ThermalZone` and the `PNP0C0F` HID, evaluating `_TMP`,
//! `_PSV`, `_CRT`, `_HOT`, `_TC1`, `_TC2`, `_AC0..9` — the typed
//! ACPI trip-point table that `acpi_thermal.c` builds in Linux.
//!
//! Filename diverges from the brief's `thermal.rs` because that name
//! is already taken by the generic registry; the brief's intent
//! ("ACPI thermal module under `power/`") is honoured.
//!
//! # Units
//!
//! Per ACPI 6.5 §11.4, every temperature object returns **tenths of
//! Kelvin (deciKelvin)**. `temperature_c_milli()` converts to
//! millidegrees Celsius so it composes with the generic
//! `power::thermal::record_temp` surface (which already speaks
//! milli-C). Callers that want plain Celsius read the milli value and
//! divide by 1000.
//!
//! `_TC1` and `_TC2` (passive cooling coefficients) are unit-free
//! integers and are returned raw.

use alloc::string::String;
use alloc::vec::Vec;

use narf_aml::eval::evaluate_method;
use narf_aml::{find_all_devices_by_hid, for_each_node_of_kind, NodeKind};

/// One ACPI Thermal Zone. Cheap to clone (just the path).
///
/// The path is the FULL namespace path the AML interpreter knows the
/// zone by — e.g. `"\\_TZ.TZ00"` or `"\\_SB.PCI0.LPCB.EC0.TZ00"`. All
/// trip-point method invocations are computed as `<path>.<method>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThermalZone {
    pub path: String,
}

/// Trip points reported by a Thermal Zone, in millidegrees Celsius.
///
/// `None` means the zone doesn't expose that trip. ACPI 6.5 §11.4
/// makes all trip points optional; the zone is still useful with
/// just `_TMP` (it lets the OS read temperature, but provides no
/// thresholds for action). The cooling governor decides what to do
/// when missing trip points leave a band unbounded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThermalTripPoints {
    /// `_CRT`: Critical temperature (system must shut down). Top of
    /// the priority order; if `_CRT` is reached, no other trip
    /// matters.
    pub critical_milli_c: Option<i32>,
    /// `_HOT`: System hot (above which the OS should hibernate or
    /// otherwise preserve user state). Optional; many laptops omit
    /// `_HOT` and only expose `_CRT`.
    pub hot_milli_c: Option<i32>,
    /// `_PSV`: Passive cooling trip. Above this, the OS should
    /// throttle CPU / GPU clocks rather than spin up fans.
    pub passive_milli_c: Option<i32>,
    /// `_AC0`..=`_AC9`: Active cooling trips. Index N drives fan
    /// level N (lower N = more aggressive cooling, per ACPI 6.5
    /// §11.4.5). `None` slots are zones with fewer than N+1 levels.
    pub active_milli_c: [Option<i32>; 10],
    /// `_TC1`: Passive cooling thermal-constant 1. Unit-free integer
    /// per ACPI 6.5 §11.4.13 (passive cooling formula coefficient).
    pub tc1: Option<u64>,
    /// `_TC2`: Passive cooling thermal-constant 2. Same shape as
    /// `_TC1`.
    pub tc2: Option<u64>,
}

/// Fan device paths returned by `_ALx` (Active cooling fan List).
///
/// ACPI 6.5 §11.4.5: `_AL0`..`_AL9` each return a Package of
/// `ObjectReference` values, one per fan device that should be
/// engaged at that active-cooling level. This struct holds the
/// string paths of those references so the thermal governor can
/// call `acpi_fan.set_control()` on each.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveCoolingList {
    /// Fully-qualified namespace paths of the fans for this level.
    /// May be empty if the zone has no `_AL{N}` or the package is empty.
    pub fans: Vec<String>,
}

/// Processor device paths returned by `_PSL` (Passive cooling
/// processor List). ACPI 6.5 §11.4.12: `_PSL` returns a Package of
/// `ObjectReference` values, one per processor that should be
/// throttled when `_PSV` is crossed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PassiveCoolingList {
    /// Fully-qualified namespace paths of the processor objects
    /// to throttle. May be empty if `_PSL` is absent.
    pub processors: Vec<String>,
}

/// Errors from a `ThermalZone` query.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ThermalError {
    /// Required method (`_TMP` typically) is absent from the zone.
    MethodMissing,
    /// `_TMP` returned 0 or 0xFFFF_FFFF — sensor offline. The Linux
    /// thermal core treats this the same way: drop the sample, don't
    /// poison the running average.
    SensorOffline,
}

/// Highest-priority trip point a given temperature has crossed.
/// Precedence per ACPI 6.5 §11.4: Critical > Hot > Passive > Active.
/// Active sub-orders by index (AC0 highest urgency to AC9 lowest);
/// within Active we report the deepest one crossed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ActiveTrip {
    None,
    /// `_ACx`: index 0..=9, where 0 is the most aggressive cooling
    /// level (also the lowest temperature threshold among the
    /// declared `_ACx` set on a sane firmware).
    Active(u8),
    /// Above `_PSV`.
    Passive,
    /// Above `_HOT`.
    Hot,
    /// Above `_CRT`. System should shut down.
    Critical,
}

impl ThermalZone {
    /// Evaluate `<path>._TMP` and return the current temperature in
    /// millidegrees Celsius. ACPI returns tenths of Kelvin; we
    /// convert.
    pub fn temperature_c_milli(&self) -> Result<i32, ThermalError> {
        let mut method = self.path.clone();
        method.push_str("._TMP");
        let v = evaluate_method(&method, &[]).map_err(|_| ThermalError::MethodMissing)?;
        let dk = v.as_integer();
        // ACPI uses 0xFFFF_FFFF as the sensor-offline sentinel; some
        // firmware reports 0 (absolute zero) when the sensor isn't
        // wired up. Both are nonsense values.
        if dk == 0 || dk == 0xFFFF_FFFF {
            return Err(ThermalError::SensorOffline);
        }
        Ok(decik_to_milli_c(dk))
    }

    /// Convenience: temperature in integer Celsius, truncating
    /// toward negative infinity. Useful for diagnostics where one
    /// degree of precision is plenty.
    pub fn temperature_c(&self) -> Result<i32, ThermalError> {
        self.temperature_c_milli().map(|m| m / 1000)
    }

    /// Read all trip points from this zone in one shot. Missing
    /// methods are returned as `None`; never errors.
    pub fn trip_points(&self) -> ThermalTripPoints {
        let mut tp = ThermalTripPoints::default();
        tp.critical_milli_c = self.read_dk_milli("_CRT");
        tp.hot_milli_c = self.read_dk_milli("_HOT");
        tp.passive_milli_c = self.read_dk_milli("_PSV");
        for i in 0..10 {
            // Method names are `_AC0` .. `_AC9`; assemble cheaply.
            let mut name = [0u8; 4];
            name[0] = b'_';
            name[1] = b'A';
            name[2] = b'C';
            name[3] = b'0' + i as u8;
            // SAFETY: bytes 0..=9 are all valid ASCII.
            let s = core::str::from_utf8(&name).unwrap();
            tp.active_milli_c[i] = self.read_dk_milli(s);
        }
        tp.tc1 = self.read_int("_TC1");
        tp.tc2 = self.read_int("_TC2");
        tp
    }

    /// Helper: read a method that returns deciKelvin, convert to
    /// milli-C. `None` if the method is missing or returned a value
    /// that doesn't make sense as a temperature.
    fn read_dk_milli(&self, leaf: &str) -> Option<i32> {
        let mut method = self.path.clone();
        method.push('.');
        method.push_str(leaf);
        let v = evaluate_method(&method, &[]).ok()?;
        let dk = v.as_integer();
        // Same sentinel-rejection as `_TMP`. A 0 deciK trip point is
        // nonsense (would mean "throttle below absolute zero").
        if dk == 0 || dk == 0xFFFF_FFFF {
            return None;
        }
        Some(decik_to_milli_c(dk))
    }

    /// Return the list of fan device paths for active cooling level `n`
    /// (`_AL0`..`_AL9`). ACPI 6.5 §11.4.5.
    ///
    /// Returns an empty `ActiveCoolingList` when the zone has no `_ALn`
    /// or when the returned Package contains no recognisable paths.
    /// The list is a snapshot — safe to hold without the AML lock.
    pub fn active_cooling_list(&self, level: u8) -> ActiveCoolingList {
        // Build method name "_ALn".
        if level > 9 {
            return ActiveCoolingList::default();
        }
        let mut name = [0u8; 4];
        name[0] = b'_';
        name[1] = b'A';
        name[2] = b'L';
        name[3] = b'0' + level;
        let leaf = core::str::from_utf8(&name).unwrap();
        let mut method = self.path.clone();
        method.push('.');
        method.push_str(leaf);
        let v = match evaluate_method(&method, &[]) {
            Ok(v) => v,
            Err(_) => return ActiveCoolingList::default(),
        };
        let fans = match v {
            narf_aml::Value::Package(pkg) => pkg
                .into_iter()
                .filter_map(|item| match item {
                    narf_aml::Value::String(s) => Some(s),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        ActiveCoolingList { fans }
    }

    /// Return the list of processor device paths for passive cooling
    /// (`_PSL`). ACPI 6.5 §11.4.12.
    ///
    /// Returns an empty `PassiveCoolingList` when the zone has no `_PSL`.
    pub fn passive_cooling_list(&self) -> PassiveCoolingList {
        let mut method = self.path.clone();
        method.push_str("._PSL");
        let v = match evaluate_method(&method, &[]) {
            Ok(v) => v,
            Err(_) => return PassiveCoolingList::default(),
        };
        let processors = match v {
            narf_aml::Value::Package(pkg) => pkg
                .into_iter()
                .filter_map(|item| match item {
                    narf_aml::Value::String(s) => Some(s),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        PassiveCoolingList { processors }
    }

    /// Helper: read a method that returns a plain integer.
    fn read_int(&self, leaf: &str) -> Option<u64> {
        let mut method = self.path.clone();
        method.push('.');
        method.push_str(leaf);
        let v = evaluate_method(&method, &[]).ok()?;
        let i = v.as_integer();
        if i == 0xFFFF_FFFF {
            None
        } else {
            Some(i)
        }
    }
}

/// Convert deciKelvin (tenths of a degree Kelvin, ACPI's native unit)
/// to millidegrees Celsius. The +/- 273.15 K offset becomes 273_150
/// milli-C.
///
/// Examples (from a Renoir 4700U DSDT):
///   3132 deciK = 313.2 K = 40.05 C = 40_050 milli-C
///   3732 deciK = 373.2 K = 100.05 C = 100_050 milli-C  (typical _CRT)
#[inline]
pub fn decik_to_milli_c(deci_k: u64) -> i32 {
    // T_milli_c = T_dk * 100 - 273_150
    // (multiplications are u64, then we cast to i32 once we've
    // subtracted the offset.)
    let scaled = deci_k.saturating_mul(100) as i64;
    (scaled - 273_150) as i32
}

/// Reverse of [`decik_to_milli_c`] — for test ergonomics.
#[inline]
pub fn milli_c_to_decik(milli_c: i32) -> u64 {
    let k = (milli_c as i64) + 273_150;
    if k <= 0 {
        return 0;
    }
    (k as u64) / 100
}

/// Apply ACPI 6.5 §11.4 trip-point precedence to a given temperature
/// (in milli-C) against a trip-point set. Returns the highest-priority
/// trip the temperature has reached or exceeded.
///
/// Precedence (highest to lowest):
///   1. Critical (`_CRT`)
///   2. Hot (`_HOT`)
///   3. Passive (`_PSV`)
///   4. Active (`_ACx`) — among declared `_ACx`, the **deepest** one
///      whose threshold the temperature has crossed wins. ACPI 6.5
///      §11.4.5: `_AC0` is the **highest-numbered cooling level**
///      (most aggressive fan speed), so among `_AC0..9` the one with
///      the **lowest** index whose threshold we crossed wins. We
///      report the index in the returned `Active(N)`.
pub fn classify(milli_c: i32, trips: &ThermalTripPoints) -> ActiveTrip {
    if let Some(crit) = trips.critical_milli_c {
        if milli_c >= crit {
            return ActiveTrip::Critical;
        }
    }
    if let Some(hot) = trips.hot_milli_c {
        if milli_c >= hot {
            return ActiveTrip::Hot;
        }
    }
    if let Some(psv) = trips.passive_milli_c {
        if milli_c >= psv {
            return ActiveTrip::Passive;
        }
    }
    // ACPI §11.4.5: _AC0 is most aggressive cooling. Conventionally
    // _AC0 > _AC1 > ... > _AC9 by temperature, so scan low index
    // first; the first one we exceed is the most-aggressive crossed.
    for i in 0..10 {
        if let Some(t) = trips.active_milli_c[i] {
            if milli_c >= t {
                return ActiveTrip::Active(i as u8);
            }
        }
    }
    ActiveTrip::None
}

/// Enumerate every ACPI Thermal Zone in the namespace. Combines two
/// sources: `NodeKind::ThermalZone` (the AML keyword-declared zones)
/// and `find_all_devices_by_hid("PNP0C0F")` (the device-tree form).
/// Deduplicated by path.
pub fn enumerate() -> Vec<ThermalZone> {
    let mut paths: Vec<String> = Vec::new();
    for_each_node_of_kind(NodeKind::ThermalZone, |n| {
        paths.push(n.path.clone());
    });
    for node in find_all_devices_by_hid("PNP0C0F") {
        // Skip duplicates — a zone CAN have both forms (one declares
        // a ThermalZone(...) block, the other declares a Device(...)
        // with HID=PNP0C0F that contains the same methods).
        if !paths.iter().any(|p| *p == node.path) {
            paths.push(node.path);
        }
    }
    paths.into_iter().map(|path| ThermalZone { path }).collect()
}

// ── Bridge to the generic `crate::thermal` registry ─────────────────
//
// `crate::thermal` is the unified cooling-policy surface (sensor +
// warn/crit + subscribe + StepPolicy). ACPI zones discovered here
// register into that registry so fan / CPU-throttle / NVMe-temp
// consumers see one cohesive zone list instead of two siloed views.
//
// Mapping rules (the trip-point precedence at `classify()` decides):
//   crit_milli  ← _CRT  (fall back to _HOT, else i32::MAX)
//   warn_milli  ← _PSV  (fall back to _AC0, else crit_milli/2)
// Zones with no sensor (`_TMP` MethodMissing) are skipped — the
// generic registry doesn't represent abstract zones.

use crate::thermal as generic;
use alloc::vec::Vec as AVec;
use narf_capabilities::{Cap, Grant};
use narf_lib::sync::IrqSafeSpinLock;

/// Map of (acpi-path → generic registry id) held for the lifetime of
/// the boot. Used by `sample_all()` to push fresh `_TMP` readings.
static BRIDGE: IrqSafeSpinLock<AVec<(String, u32)>> = IrqSafeSpinLock::new(AVec::new());

/// Discover every ACPI Thermal Zone, register it with the generic
/// `crate::thermal` registry, and remember the (path → id) mapping so
/// `sample_all` can push live `_TMP` readings later.
///
/// Returns the number of zones registered. Idempotent — call once at
/// Stage::Late or whenever the namespace is stable; a second call
/// after the bridge is populated re-walks but does NOT double-register
/// existing paths.
pub fn register_with_generic_registry(cap: &Cap<generic::Thermal, Grant>) -> usize {
    let mut bridge = BRIDGE.lock();
    let mut newly_registered = 0usize;
    for zone in enumerate() {
        if bridge.iter().any(|(p, _)| *p == zone.path) {
            continue;
        }
        // Skip sensorless zones — generic registry assumes a temperature
        // can always be reported, and ACPI zones that exist purely to
        // host trip-points without a `_TMP` aren't useful to cooling
        // policy.
        if zone.temperature_c_milli().is_err() {
            continue;
        }
        let trips = zone.trip_points();
        let crit_milli = trips
            .critical_milli_c
            .or(trips.hot_milli_c)
            .unwrap_or(i32::MAX);
        let warn_milli = trips
            .passive_milli_c
            .or(trips.active_milli_c[0])
            .unwrap_or_else(|| crit_milli / 2);
        if let Ok(id) = generic::register_zone(cap, &zone.path, warn_milli, crit_milli) {
            bridge.push((zone.path.clone(), id));
            newly_registered += 1;
        }
    }
    newly_registered
}

/// Walk every bridged zone, read its current `_TMP`, and push the
/// reading into the generic registry. Returns the count of successful
/// samples. Sensor-offline zones are quietly skipped (the registry
/// keeps its last reading rather than poisoning the average).
///
/// Call from a periodic pump — Linux's thermal core polls at ~1 Hz;
/// match that or slower to keep AML eval cost off the critical path.
pub fn sample_all() -> usize {
    let mut succeeded = 0usize;
    for (path, id) in BRIDGE.lock().iter() {
        let zone = ThermalZone { path: path.clone() };
        if let Ok(milli_c) = zone.temperature_c_milli() {
            if generic::record_temp(*id, milli_c).is_ok() {
                succeeded += 1;
            }
        }
    }
    succeeded
}

#[cfg(test)]
#[doc(hidden)]
pub fn __test_clear_bridge() {
    BRIDGE.lock().clear();
}

// ── Tests ───────────────────────────────────────────────────────────

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_acpi_thermal_decik_round_trip() -> TestResult {
        // 313.2 K = 40.05 C → 40_050 milli-C
        if decik_to_milli_c(3132) != 40_050 {
            return TestResult::Fail("3132 deciK should convert to 40_050 milli-C");
        }
        // 373.2 K = 100.05 C → 100_050 milli-C (typical _CRT)
        if decik_to_milli_c(3732) != 100_050 {
            return TestResult::Fail("3732 deciK should convert to 100_050 milli-C");
        }
        // 2731 deciK = 273.1 K = -0.05 C → -50 milli-C
        if decik_to_milli_c(2731) != -50 {
            return TestResult::Fail("2731 deciK should convert to -50 milli-C");
        }
        // Round-trip: milli_c → decik → milli_c. Lossy (100 milli-C
        // per deciK) but should round to within 99 milli-C.
        let m = 40_050i32;
        let back = decik_to_milli_c(milli_c_to_decik(m));
        if (back - m).abs() > 100 {
            return TestResult::Fail("milli_c round-trip drifted > 100 milli-C");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/acpi_thermal", smoke_acpi_thermal_decik_round_trip);

    fn smoke_acpi_thermal_classify_precedence_critical_wins() -> TestResult {
        // Trips: _CRT=100 C, _HOT=95 C, _PSV=85 C, _AC0=75 C, _AC1=65 C.
        // The classifier must report Critical when t >= _CRT, even
        // though every lower trip is also crossed.
        let mut trips = ThermalTripPoints::default();
        trips.critical_milli_c = Some(100_000);
        trips.hot_milli_c = Some(95_000);
        trips.passive_milli_c = Some(85_000);
        trips.active_milli_c[0] = Some(75_000);
        trips.active_milli_c[1] = Some(65_000);

        if classify(105_000, &trips) != ActiveTrip::Critical {
            return TestResult::Fail("105 C with _CRT=100 should be Critical");
        }
        if classify(97_000, &trips) != ActiveTrip::Hot {
            return TestResult::Fail("97 C with _HOT=95 should be Hot (not Passive/Active)");
        }
        if classify(87_000, &trips) != ActiveTrip::Passive {
            return TestResult::Fail("87 C with _PSV=85 should be Passive");
        }
        // 77 C — exceeds _AC0 (75) but not _PSV. Should pick the
        // most-aggressive crossed _ACx = _AC0.
        match classify(77_000, &trips) {
            ActiveTrip::Active(0) => {}
            other => {
                let _ = other;
                return TestResult::Fail("77 C should classify as Active(0)");
            }
        }
        // 70 C — exceeds _AC1 only.
        match classify(70_000, &trips) {
            ActiveTrip::Active(1) => {}
            _ => return TestResult::Fail("70 C should classify as Active(1)"),
        }
        // 50 C — below everything.
        if classify(50_000, &trips) != ActiveTrip::None {
            return TestResult::Fail("50 C with all trips above should be None");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "power/acpi_thermal",
        smoke_acpi_thermal_classify_precedence_critical_wins
    );

    fn smoke_acpi_thermal_classify_sparse_trips() -> TestResult {
        // Many real-world DSDTs only export _CRT + _TMP. Confirm the
        // classifier handles unbounded ranges gracefully.
        let mut trips = ThermalTripPoints::default();
        trips.critical_milli_c = Some(100_000);
        // No _HOT / _PSV / _AC*.

        if classify(99_999, &trips) != ActiveTrip::None {
            return TestResult::Fail("99.999 C with only _CRT=100 should be None");
        }
        if classify(100_000, &trips) != ActiveTrip::Critical {
            return TestResult::Fail("100 C at _CRT boundary should be Critical");
        }
        // No trips at all → always None.
        let empty = ThermalTripPoints::default();
        if classify(150_000, &empty) != ActiveTrip::None {
            return TestResult::Fail("150 C with no trips should be None (sensor still streams)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "power/acpi_thermal",
        smoke_acpi_thermal_classify_sparse_trips
    );

    fn smoke_acpi_thermal_tmp_known_values_3531_3631() -> TestResult {
        // Renoir 4700U DSDT has _CRT = 3731 and typical idle _TMP ~3531.
        // 3531 deciK = 353.1 K = 79.95 C = 79_950 milli-C.
        if decik_to_milli_c(3531) != 79_950 {
            return TestResult::Fail("3531 deciK must map to 79_950 milli-C (~80 C)");
        }
        // 3631 deciK = 363.1 K = 89.95 C = 89_950 milli-C (~90 C).
        if decik_to_milli_c(3631) != 89_950 {
            return TestResult::Fail("3631 deciK must map to 89_950 milli-C (~90 C)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "power/acpi_thermal",
        smoke_acpi_thermal_tmp_known_values_3531_3631
    );

    fn smoke_acpi_thermal_psv_trip_passive_cooling() -> TestResult {
        // _PSV = 75 C = 75_000 milli-C. Boundary and above → Passive.
        let mut trips = ThermalTripPoints::default();
        trips.passive_milli_c = Some(75_000);

        // Below PSV: still None.
        if classify(74_999, &trips) != ActiveTrip::None {
            return TestResult::Fail("74.999 C just below _PSV=75 should be None");
        }
        // Exactly at PSV boundary (inclusive): Passive.
        if classify(75_000, &trips) != ActiveTrip::Passive {
            return TestResult::Fail("75 C at _PSV=75 boundary must be Passive");
        }
        // Well above PSV: Passive (no CRT/HOT set).
        if classify(95_000, &trips) != ActiveTrip::Passive {
            return TestResult::Fail("95 C with only _PSV=75 must remain Passive");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "power/acpi_thermal",
        smoke_acpi_thermal_psv_trip_passive_cooling
    );

    fn smoke_acpi_thermal_acx_fan_engagement() -> TestResult {
        // _AC0 = 70 C, _AC1 = 60 C, _PSV = 80 C.
        // ACPI §11.4.5: Passive > Active; lower index is more aggressive.
        let mut trips = ThermalTripPoints::default();
        trips.passive_milli_c = Some(80_000);
        trips.active_milli_c[0] = Some(70_000);
        trips.active_milli_c[1] = Some(60_000);

        // 65 C: above _AC1 (60) but below _AC0 (70) → Active(1).
        match classify(65_000, &trips) {
            ActiveTrip::Active(1) => {}
            _ => return TestResult::Fail("65 C should be Active(1)"),
        }
        // 72 C: above _AC0 (70) but below _PSV (80) → Active(0).
        match classify(72_000, &trips) {
            ActiveTrip::Active(0) => {}
            _ => return TestResult::Fail("72 C should be Active(0) (not Passive yet)"),
        }
        // 82 C: above _PSV (80) → Passive wins over any Active.
        if classify(82_000, &trips) != ActiveTrip::Passive {
            return TestResult::Fail("82 C above _PSV should be Passive, not Active");
        }
        // 55 C: below all thresholds → None.
        if classify(55_000, &trips) != ActiveTrip::None {
            return TestResult::Fail("55 C below all trips should be None");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/acpi_thermal", smoke_acpi_thermal_acx_fan_engagement);
}
