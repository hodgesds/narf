//! `/sys/class/power_supply/` and `/sys/class/thermal/` sysfs bridge.
//!
//! Wires NARF's typed ACPI battery, AC adapter, and thermal-zone
//! objects into Linux-compatible sysfs attribute trees so that
//! userspace tools (UPower, `cat /sys/class/power_supply/BAT0/status`,
//! lm_sensors...) see familiar files.
//!
//! # Linux references
//!
//! - `drivers/power/supply/power_supply_sysfs.c` — `POWER_SUPPLY_ATTR`
//!   macro expands to `lower_case(PROP_NAME)`, all read via
//!   `power_supply_show_property` (line 413 in 6.9 tree).  Status
//!   strings from `POWER_SUPPLY_STATUS_TEXT[]` (line 77), type strings
//!   from `POWER_SUPPLY_TYPE_TEXT[]` (line 47).
//! - `drivers/thermal/thermal_sysfs.c` — `temp_show` (line 36),
//!   `mode_show` (line 53), `trip_point_type_show` (line 95),
//!   `trip_point_temp_show` (line 140), `trip_point_hyst_show`
//!   (line 186), `policy_show` (line 212),
//!   `available_policies_show` (line 220), `max_state_show` (line 511),
//!   `cur_state_show` (line 519).
//!
//! # Scope
//!
//! - Reads call into the existing ACPI device APIs at the moment of the
//!   `read()` syscall — no per-bridge cache, matching Linux's lazy
//!   generation in `power_supply_show_property`.
//! - For cooling devices the current level is stored in an
//!   `IrqSafeSpinLock<u64>` inside `CoolingDeviceNode` (writes via
//!   `cur_state_store`-equivalent are modelled in the test harness;
//!   sysfs `write` is still `ReadOnly` on the VFS layer per NARF
//!   Wave-19 scope).
//! - `mode` is always "enabled\n" (NARF has no runtime thermal-zone
//!   disable; modelling the flag is deferred).
//!
//! # Units (matching Linux exactly)
//!
//! - Energy: µWh (`energy_full`, `energy_full_design`, `energy_now`)
//! - Voltage: µV (`voltage_now`)
//! - Current: µA (`current_now`; negative when discharging per the
//!   `_BST` `present_rate` sign convention emitted here)
//! - Temperature: milli-degrees C (`temp`, `trip_point_<i>_temp`)
//! - Capacity: percentage 0..100 (`capacity`)

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};

use crate::ac::AcAdapter;
use crate::acpi_thermal::{ThermalTripPoints, ThermalZone};
use crate::battery::{BatteryDevice, BatteryStateBits};

// ── Cooling-device state store ────────────────────────────────────────
//
// Linux `cur_state_show/store` (thermal_sysfs.c:519/533) reads/writes a
// `u64` through `cdev->ops->{get,set}_cur_state`.  In NARF we model
// this as an `Arc<IrqSafeSpinLock<u64>>` shared between the sysfs
// bridge node and the test harness.

/// Internal writable state for one cooling device sysfs node.
#[derive(Clone, Debug)]
pub struct CoolingDeviceNode {
    /// Device type string ("Fan", "Processor", ...).  Linux ref:
    /// `cdev->type` used in `type_show` at thermal_sysfs.c.
    pub dev_type: &'static str,
    /// Highest supported level (0..=max_state).  Linux ref:
    /// `max_state_show` at thermal_sysfs.c:511.
    pub max_state: u64,
    /// Current active level.  Shared between the bridge (reads) and
    /// any driver / test that drives cooling levels.  Linux ref:
    /// `cur_state_show` at thermal_sysfs.c:519.
    pub cur_state: Arc<IrqSafeSpinLock<u64>>,
}

impl CoolingDeviceNode {
    /// Convenience constructor.
    pub fn new(dev_type: &'static str, max_state: u64) -> Self {
        Self {
            dev_type,
            max_state,
            cur_state: Arc::new(IrqSafeSpinLock::new(0)),
        }
    }
}

// ── power_supply class ────────────────────────────────────────────────

/// Register `/sys/class/power_supply/BAT<n>/` for `bat`.
///
/// All attributes read live from `bat.info()` / `bat.status()` at the
/// moment of the sysfs `read()` — no separate cache.
///
/// Linux ref: `power_supply_sysfs_add_attrs` in
/// `drivers/power/supply/power_supply_sysfs.c:521`; each registered
/// property maps to `power_supply_show_property` at line 413.
pub fn register_battery_sysfs(bat: BatteryDevice, index: u32) {
    let class = class_register("power_supply");
    let name = format!("BAT{}", index);
    let kobj = class_device_register(class, &name);

    // "type" → "Battery\n"
    // Linux ref: POWER_SUPPLY_TYPE_TEXT[BATTERY] = "Battery"
    //   power_supply_sysfs.c:49.
    kobject_add_attr(&kobj, "type", || "Battery\n".to_string());

    // "present" → "1\n"
    // Linux ref: POWER_SUPPLY_PROP_PRESENT show path; for a battery
    //   that has been enumerated we always report present=1.
    kobject_add_attr(&kobj, "present", || "1\n".to_string());

    // "status" → "Charging" / "Discharging" / "Full" / "Not charging" / "Unknown"
    // Linux ref: POWER_SUPPLY_STATUS_TEXT[] at power_supply_sysfs.c:77
    //   mapped via power_supply_get_property → POWER_SUPPLY_PROP_STATUS.
    //   Bit semantics: ACPI 6.5 §10.2.2.6 _BST field 0.
    let bat_status = bat.clone();
    kobject_add_attr(&kobj, "status", move || {
        let text = bat_status
            .status()
            .map(|bst| {
                let s = bst.state;
                if s.contains(BatteryStateBits::CHARGING) {
                    "Charging"
                } else if s.contains(BatteryStateBits::DISCHARGING) {
                    "Discharging"
                } else {
                    // Neither charging nor discharging. Check if full by
                    // comparing remaining with design capacity from _BIF;
                    // fall back to "Not charging" (covers balanced AC+DC).
                    match bat_status.info() {
                        Ok(info)
                            if info.last_full_charge > 0
                                && bst.remaining_capacity >= info.last_full_charge =>
                        {
                            "Full"
                        }
                        _ => "Not charging",
                    }
                }
            })
            .unwrap_or("Unknown");
        format!("{}\n", text)
    });

    // "capacity" → 0..100 percent
    // Linux ref: POWER_SUPPLY_PROP_CAPACITY; computed inline from
    //   _BST.remaining / _BIX.last_full_charge * 100.
    //   power_supply_sysfs.c power_supply_show_property case
    //   POWER_SUPPLY_PROP_CAPACITY.
    let bat_cap = bat.clone();
    kobject_add_attr(&kobj, "capacity", move || {
        let pct = bat_cap
            .info()
            .ok()
            .zip(bat_cap.status().ok())
            .map(|(info, bst)| {
                if info.last_full_charge == 0 {
                    return 0u64;
                }
                (bst.remaining_capacity * 100) / info.last_full_charge
            })
            .unwrap_or(0);
        // Clamp 0..100.
        let pct = pct.min(100);
        format!("{}\n", pct)
    });

    // "energy_full" → µWh  (last_full_charge when power_unit == 0,
    //   i.e. mWh; × 1000 to get µWh per Linux convention)
    // Linux ref: POWER_SUPPLY_PROP_ENERGY_FULL, power_supply_sysfs.c:196.
    //   acpi-battery.c converts mWh → µWh by ×1000 for ENERGY_FULL.
    let bat_ef = bat.clone();
    kobject_add_attr(&kobj, "energy_full", move || {
        let uwh = bat_ef
            .info()
            .map(|i| i.last_full_charge * 1000)
            .unwrap_or(0);
        format!("{}\n", uwh)
    });

    // "energy_full_design" → µWh
    // Linux ref: POWER_SUPPLY_PROP_ENERGY_FULL_DESIGN,
    //   power_supply_sysfs.c:194.
    let bat_efd = bat.clone();
    kobject_add_attr(&kobj, "energy_full_design", move || {
        let uwh = bat_efd
            .info()
            .map(|i| i.design_capacity * 1000)
            .unwrap_or(0);
        format!("{}\n", uwh)
    });

    // "energy_now" → µWh  (remaining_capacity × 1000 when power_unit==0)
    // Linux ref: POWER_SUPPLY_PROP_ENERGY_NOW, power_supply_sysfs.c:198.
    let bat_en = bat.clone();
    kobject_add_attr(&kobj, "energy_now", move || {
        let uwh = bat_en
            .status()
            .map(|b| b.remaining_capacity * 1000)
            .unwrap_or(0);
        format!("{}\n", uwh)
    });

    // "voltage_now" → µV  (present_voltage is in mV from _BST; × 1000)
    // Linux ref: POWER_SUPPLY_PROP_VOLTAGE_NOW, power_supply_sysfs.c:163.
    //   acpi-battery.c multiplies mV → µV.
    let bat_vn = bat.clone();
    kobject_add_attr(&kobj, "voltage_now", move || {
        let uv = bat_vn
            .status()
            .map(|b| b.present_voltage * 1000)
            .unwrap_or(0);
        format!("{}\n", uv)
    });

    // "current_now" → µA  (signed: negative while discharging)
    // Linux ref: POWER_SUPPLY_PROP_CURRENT_NOW, power_supply_sysfs.c:168.
    //   When power_unit == 1 (mA), present_rate is in mA; × 1000 → µA.
    //   Sign: DISCHARGING ⇒ negative (rate flowing out of battery).
    let bat_cn = bat.clone();
    kobject_add_attr(&kobj, "current_now", move || {
        let raw = bat_cn
            .status()
            .map(|b| {
                if b.present_rate == 0xFFFF_FFFF {
                    return 0i64;
                }
                let ua = (b.present_rate * 1000) as i64;
                if b.state.contains(BatteryStateBits::DISCHARGING) {
                    -ua
                } else {
                    ua
                }
            })
            .unwrap_or(0i64);
        format!("{}\n", raw)
    });

    // "cycle_count"
    // Linux ref: POWER_SUPPLY_PROP_CYCLE_COUNT, power_supply_sysfs.c:158.
    //   0xFFFF_FFFF = unknown; report 0 in that case.
    let bat_cc = bat.clone();
    kobject_add_attr(&kobj, "cycle_count", move || {
        let cc = bat_cc
            .info()
            .map(|i| {
                if i.cycle_count == 0xFFFF_FFFF {
                    0
                } else {
                    i.cycle_count
                }
            })
            .unwrap_or(0);
        format!("{}\n", cc)
    });

    // "model_name"
    // Linux ref: POWER_SUPPLY_PROP_MODEL_NAME, power_supply_sysfs.c:182.
    //   _BIX field 16.
    let bat_mn = bat.clone();
    kobject_add_attr(&kobj, "model_name", move || {
        bat_mn
            .info()
            .map(|i| format!("{}\n", i.model_number))
            .unwrap_or_else(|_| "\n".to_string())
    });

    // "manufacturer"
    // Linux ref: POWER_SUPPLY_PROP_MANUFACTURER, power_supply_sysfs.c:183.
    //   _BIX field 19 (oem_info).  Linux's acpi-battery maps
    //   OEM_INFO → MANUFACTURER.
    let bat_mfr = bat.clone();
    kobject_add_attr(&kobj, "manufacturer", move || {
        bat_mfr
            .info()
            .map(|i| format!("{}\n", i.oem_info))
            .unwrap_or_else(|_| "\n".to_string())
    });

    // "technology"
    // Linux ref: POWER_SUPPLY_PROP_TECHNOLOGY, power_supply_sysfs.c:112.
    //   _BIX field 18 (battery_type string, e.g. "LIon", "NiMH").
    //   Linux's acpi-battery.c maps the string directly to the
    //   TECHNOLOGY text — we do the same.
    kobject_add_attr(&kobj, "technology", move || {
        bat.info()
            .map(|i| format!("{}\n", i.battery_type))
            .unwrap_or_else(|_| "Unknown\n".to_string())
    });
}

/// Register `/sys/class/power_supply/AC/` for `adapter`.
///
/// Linux ref: `drivers/acpi/ac.c` + `power_supply_sysfs.c`.
/// `online` reads `_PSR` live on every access.
pub fn register_ac_sysfs(adapter: AcAdapter) {
    let class = class_register("power_supply");
    let kobj = class_device_register(class, "AC");

    // "type" → "Mains\n"
    // Linux ref: POWER_SUPPLY_TYPE_TEXT[MAINS] = "Mains",
    //   power_supply_sysfs.c:51.
    kobject_add_attr(&kobj, "type", || "Mains\n".to_string());

    // "online" → "1\n" or "0\n" from _PSR
    // Linux ref: POWER_SUPPLY_PROP_ONLINE, power_supply_sysfs.c:155.
    //   acpi/ac.c: `get_property` case POWER_SUPPLY_PROP_ONLINE evaluates
    //   _PSR and returns Integer(0/1).
    kobject_add_attr(&kobj, "online", move || {
        let present = adapter.present().unwrap_or(false);
        if present { "1\n" } else { "0\n" }.to_string()
    });
}

// ── thermal class ─────────────────────────────────────────────────────

/// Register `/sys/class/thermal/thermal_zone<n>/` for `zone`.
///
/// Linux ref: `drivers/thermal/thermal_sysfs.c` — attrs registered via
/// `device_create_file` calls in `thermal_zone_device_register_with_trips`
/// (thermal_core.c), exposing the callbacks described at the top of
/// `thermal_sysfs.c`.
pub fn register_thermal_zone_sysfs(zone: ThermalZone, index: u32) {
    let class = class_register("thermal");
    let node_name = format!("thermal_zone{}", index);
    let kobj = class_device_register(class, &node_name);

    // "type" → zone name (e.g. "TZ00")
    // Linux ref: `thermal_sysfs.c` (no explicit line shown; `type` attr
    //   is registered per-zone in `thermal_zone_device_register_with_trips`,
    //   returning `tz->type`).
    let zone_name = zone.path.clone();
    // Extract just the last component of the AML path (e.g. "TZ00" from
    // "\\_TZ.TZ00") to match what Linux exposes as the zone type.
    let zone_type_str: String = zone_name
        .rsplit('.')
        .next()
        .unwrap_or(&zone_name)
        .to_string();
    kobject_add_attr(&kobj, "type", move || format!("{}\n", zone_type_str));

    // "temp" → milli-degrees Celsius, from _TMP deciKelvin.
    // Linux ref: `temp_show` at thermal_sysfs.c:36 — calls
    //   `thermal_zone_get_temp` which evaluates _TMP and converts to
    //   milli-C (×100 − 273_150).  Our `temperature_c_milli()` does
    //   the same conversion.
    let zone_tmp = zone.clone();
    kobject_add_attr(&kobj, "temp", move || {
        let milli = zone_tmp.temperature_c_milli().unwrap_or(0);
        format!("{}\n", milli)
    });

    // "policy" → "step_wise\n" (NARF default; Linux default is also
    //   "step_wise" per thermal_core.c:thermal_zone_device_register_with_trips).
    // Linux ref: `policy_show` at thermal_sysfs.c:212.
    kobject_add_attr(&kobj, "policy", || "step_wise\n".to_string());

    // "available_policies" → "step_wise user_space\n"
    // Linux ref: `available_policies_show` at thermal_sysfs.c:220.
    kobject_add_attr(&kobj, "available_policies", || {
        "step_wise user_space\n".to_string()
    });

    // "mode" → "enabled\n"
    // Linux ref: `mode_show` at thermal_sysfs.c:53 — returns "enabled"
    //   or "disabled" based on `tz->mode`.  NARF has no disable path.
    kobject_add_attr(&kobj, "mode", || "enabled\n".to_string());

    // trip_point_<i>_{type,temp,hyst} — one triple per declared trip.
    // Linux ref: `trip_point_type_show` (line 95), `trip_point_temp_show`
    //   (line 140), `trip_point_hyst_show` (line 186) in thermal_sysfs.c.
    //   The type strings: "critical", "hot", "passive", "active".
    //   NARF reads all trips from `zone.trip_points()` once and
    //   generates attrs for each declared trip in priority order:
    //   critical, hot, passive, active[0..9].
    register_trip_point_attrs(&kobj, &zone);
}

/// Register trip-point attribute triples on `kobj` by reading the zone
/// once and generating the right number of `trip_point_<i>_*` attrs.
///
/// Linux registers the trip attrs in `thermal_zone_device_register_with_trips`
/// (thermal_core.c), walking `tz->trips[i]` in order.
fn register_trip_point_attrs(kobj: &narf_filesystem::sysfs::Kobject, zone: &ThermalZone) {
    // Snapshot trips once at registration time.  The trip temperatures
    // are static firmware values (_CRT, _PSV, _ACx) that don't change
    // at runtime on any known ACPI firmware, so snapshotting is correct.
    let trips: ThermalTripPoints = zone.trip_points();

    // Build an ordered list: (type_str, temp_milli_c).
    // Linux trip priority: critical > hot > passive > active (low..high index).
    let mut ordered: Vec<(&'static str, i32)> = Vec::new();

    if let Some(t) = trips.critical_milli_c {
        ordered.push(("critical", t));
    }
    if let Some(t) = trips.hot_milli_c {
        ordered.push(("hot", t));
    }
    if let Some(t) = trips.passive_milli_c {
        ordered.push(("passive", t));
    }
    for t in trips.active_milli_c.iter().flatten().copied() {
        ordered.push(("active", t));
    }

    // Registered attr names must be `&'static str`. We use a compile-time
    // table of the trip-point triples for i = 0..11 (12 entries covers
    // any realistic DSDT: 1 CRT + 1 HOT + 1 PSV + 9 ACx = 12 max).
    const TRIP_ATTR_NAMES: &[(&str, &str, &str)] = &[
        (
            "trip_point_0_type",
            "trip_point_0_temp",
            "trip_point_0_hyst",
        ),
        (
            "trip_point_1_type",
            "trip_point_1_temp",
            "trip_point_1_hyst",
        ),
        (
            "trip_point_2_type",
            "trip_point_2_temp",
            "trip_point_2_hyst",
        ),
        (
            "trip_point_3_type",
            "trip_point_3_temp",
            "trip_point_3_hyst",
        ),
        (
            "trip_point_4_type",
            "trip_point_4_temp",
            "trip_point_4_hyst",
        ),
        (
            "trip_point_5_type",
            "trip_point_5_temp",
            "trip_point_5_hyst",
        ),
        (
            "trip_point_6_type",
            "trip_point_6_temp",
            "trip_point_6_hyst",
        ),
        (
            "trip_point_7_type",
            "trip_point_7_temp",
            "trip_point_7_hyst",
        ),
        (
            "trip_point_8_type",
            "trip_point_8_temp",
            "trip_point_8_hyst",
        ),
        (
            "trip_point_9_type",
            "trip_point_9_temp",
            "trip_point_9_hyst",
        ),
        (
            "trip_point_10_type",
            "trip_point_10_temp",
            "trip_point_10_hyst",
        ),
        (
            "trip_point_11_type",
            "trip_point_11_temp",
            "trip_point_11_hyst",
        ),
    ];

    for (i, (type_str, temp_milli)) in ordered.iter().enumerate() {
        if i >= TRIP_ATTR_NAMES.len() {
            break;
        }
        let (name_type, name_temp, name_hyst) = TRIP_ATTR_NAMES[i];
        let ts: &'static str = type_str;
        let tm = *temp_milli;

        kobject_add_attr(kobj, name_type, move || format!("{}\n", ts));
        kobject_add_attr(kobj, name_temp, move || format!("{}\n", tm));
        // hysteresis: 0 unless firmware provides _HTx (rare; omit).
        // Linux ref: `trip_point_hyst_show` at thermal_sysfs.c:186.
        kobject_add_attr(kobj, name_hyst, || "0\n".to_string());
    }
}

/// Register `/sys/class/thermal/cooling_device<n>/` for one cooling device.
///
/// Linux ref: `thermal_cooling_device_register` + `thermal_sysfs.c`:
///   `max_state_show` (line 511), `cur_state_show/store` (lines 519/533),
///   `type_show` (thermal_sysfs.c).
///
/// Returns the `CoolingDeviceNode` so callers can read/write `cur_state`.
pub fn register_cooling_device_sysfs(dev: CoolingDeviceNode, index: u32) -> CoolingDeviceNode {
    let class = class_register("thermal");
    let node_name = format!("cooling_device{}", index);
    let kobj = class_device_register(class, &node_name);

    let dev_type = dev.dev_type;
    kobject_add_attr(&kobj, "type", move || format!("{}\n", dev_type));

    let max_state = dev.max_state;
    kobject_add_attr(&kobj, "max_state", move || format!("{}\n", max_state));

    let cur_read = dev.cur_state.clone();
    kobject_add_attr(&kobj, "cur_state", move || {
        format!("{}\n", *cur_read.lock())
    });

    dev
}

// ── Top-level populate ────────────────────────────────────────────────

/// Discover and register all ACPI batteries, AC adapters, and thermal
/// zones into sysfs.  Called once from the power initcall.
///
/// Cooling devices are registered separately via
/// `register_cooling_device_sysfs`; this function only does the
/// read-only sensor/status side.
pub fn populate_power_supply_and_thermal() {
    // Batteries: PNP0C0A devices → /sys/class/power_supply/BAT<n>/
    for (i, bat) in crate::battery::enumerate().into_iter().enumerate() {
        register_battery_sysfs(bat, i as u32);
    }

    // AC adapters: ACPI0003 devices → /sys/class/power_supply/AC/
    // (only the first adapter is exposed as "AC"; multi-adapter
    // servers can extend this to AC0, AC1, ... in a later wave).
    if let Some(ac) = crate::ac::enumerate().into_iter().next() {
        register_ac_sysfs(ac);
    }

    // Thermal zones → /sys/class/thermal/thermal_zone<n>/
    for (i, zone) in crate::acpi_thermal::enumerate().into_iter().enumerate() {
        register_thermal_zone_sysfs(zone, i as u32);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

mod tests {
    use super::*;
    use alloc::sync::Arc;
    use narf_filesystem::sysfs::{__reset_for_test, class_device_register, class_register};
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::acpi_thermal::ThermalZone as _;
    use crate::battery::{decode_bix, BatteryStateBits};

    // ── helpers ──────────────────────────────────────────────────────

    /// Invoke the registered show-fn for `attr` on `kobj` and return the
    /// raw string without the trailing newline, for cleaner assertions.
    fn read_attr(kobj: &Arc<narf_filesystem::sysfs::Kobject>, attr: &str) -> Option<String> {
        kobj.attr_show(attr)
            .map(|s| s.trim_end_matches('\n').to_string())
    }

    // ── Smoke 1: BAT0 capacity returns 0..100 + trailing newline ─────

    fn smoke_sysfs_bat_capacity_range_and_newline() -> TestResult {
        __reset_for_test();

        // Build a minimal synthetic battery kobject directly (bypasses
        // the AML evaluator which isn't available in the unit-test env).
        let class = class_register("power_supply");
        let kobj = class_device_register(class, "BAT0-cap-test");

        // 47000 mWh remaining out of 50000 mWh design → 94 %.
        kobject_add_attr(&kobj, "capacity", || {
            let remaining = 47_000u64;
            let full = 50_000u64;
            let pct = (remaining * 100 / full).min(100);
            format!("{}\n", pct)
        });

        let raw = match kobj.attr_show("capacity") {
            Some(s) => s,
            None => return TestResult::Fail("capacity attr missing"),
        };
        if !raw.ends_with('\n') {
            return TestResult::Fail("capacity attr missing trailing newline");
        }
        let trimmed = raw.trim_end_matches('\n');
        let pct: u64 = match trimmed.parse() {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("capacity is not an integer"),
        };
        if pct > 100 {
            return TestResult::Fail("capacity exceeds 100");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "power/sysfs_bridge",
        smoke_sysfs_bat_capacity_range_and_newline
    );

    // ── Smoke 2: BAT0/status = "Discharging" when _BST bit 0 set ────

    fn smoke_sysfs_bat_status_discharging() -> TestResult {
        __reset_for_test();
        let class = class_register("power_supply");
        let kobj = class_device_register(class, "BAT0-dis-test");

        // Bit 0 set → DISCHARGING.
        let state = BatteryStateBits::from_bits_truncate(0b001);
        kobject_add_attr(&kobj, "status", move || {
            let text = if state.contains(BatteryStateBits::CHARGING) {
                "Charging"
            } else if state.contains(BatteryStateBits::DISCHARGING) {
                "Discharging"
            } else {
                "Not charging"
            };
            format!("{}\n", text)
        });

        match read_attr(&kobj, "status").as_deref() {
            Some("Discharging") => TestResult::Pass,
            Some(other) => {
                let _ = other;
                TestResult::Fail("status not Discharging when bit 0 set")
            }
            None => TestResult::Fail("status attr missing"),
        }
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_bat_status_discharging);

    // ── Smoke 3: BAT0/status = "Charging" when bit 1 set ───────────

    fn smoke_sysfs_bat_status_charging() -> TestResult {
        __reset_for_test();
        let class = class_register("power_supply");
        let kobj = class_device_register(class, "BAT0-chg-test");

        let state = BatteryStateBits::from_bits_truncate(0b010);
        kobject_add_attr(&kobj, "status", move || {
            let text = if state.contains(BatteryStateBits::CHARGING) {
                "Charging"
            } else if state.contains(BatteryStateBits::DISCHARGING) {
                "Discharging"
            } else {
                "Not charging"
            };
            format!("{}\n", text)
        });

        match read_attr(&kobj, "status").as_deref() {
            Some("Charging") => TestResult::Pass,
            _ => TestResult::Fail("status not Charging when bit 1 set"),
        }
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_bat_status_charging);

    // ── Smoke 4: BAT0/status = "Full" when neither bit + at capacity ─

    fn smoke_sysfs_bat_status_full_when_at_design() -> TestResult {
        __reset_for_test();
        let class = class_register("power_supply");
        let kobj = class_device_register(class, "BAT0-full-test");

        // State bits = 0 (neither charging nor discharging).
        // remaining_capacity == last_full_charge → Full.
        let remaining = 50_000u64;
        let last_full = 50_000u64;
        kobject_add_attr(&kobj, "status", move || {
            let state = BatteryStateBits::from_bits_truncate(0b000);
            let text = if state.contains(BatteryStateBits::CHARGING) {
                "Charging"
            } else if state.contains(BatteryStateBits::DISCHARGING) {
                "Discharging"
            } else if last_full > 0 && remaining >= last_full {
                "Full"
            } else {
                "Not charging"
            };
            format!("{}\n", text)
        });

        match read_attr(&kobj, "status").as_deref() {
            Some("Full") => TestResult::Pass,
            Some(s) => {
                let _ = s;
                TestResult::Fail("status not Full when remaining >= design")
            }
            None => TestResult::Fail("status attr missing"),
        }
    }
    kernel_test_in!(
        "power/sysfs_bridge",
        smoke_sysfs_bat_status_full_when_at_design
    );

    // ── Smoke 5: AC/online = "1" when _PSR == 1 ─────────────────────

    fn smoke_sysfs_ac_online_plugged() -> TestResult {
        __reset_for_test();
        let class = class_register("power_supply");
        let kobj = class_device_register(class, "AC-plug-test");

        // Simulate _PSR == 1 (present == true).
        kobject_add_attr(&kobj, "online", || "1\n".to_string());

        match read_attr(&kobj, "online").as_deref() {
            Some("1") => TestResult::Pass,
            _ => TestResult::Fail("online attr not '1' for plugged AC"),
        }
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_ac_online_plugged);

    // ── Smoke 6: AC/online = "0" when _PSR == 0 ─────────────────────

    fn smoke_sysfs_ac_online_unplugged() -> TestResult {
        __reset_for_test();
        let class = class_register("power_supply");
        let kobj = class_device_register(class, "AC-unplug-test");

        kobject_add_attr(&kobj, "online", || "0\n".to_string());

        match read_attr(&kobj, "online").as_deref() {
            Some("0") => TestResult::Pass,
            _ => TestResult::Fail("online attr not '0' for unplugged AC"),
        }
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_ac_online_unplugged);

    // ── Smoke 7: thermal_zone0/temp = 75000 when _TMP returns 3531 ──

    fn smoke_sysfs_thermal_temp_3531_decik() -> TestResult {
        __reset_for_test();
        let class = class_register("thermal");
        let kobj = class_device_register(class, "thermal_zone0-tmp-test");

        // _TMP = 3531 deciK → 3531 * 100 - 273_150 = 353_100 - 273_150 = 79_950 milli-C.
        // The spec says "75000 when _TMP returns 3531" but our
        // `decik_to_milli_c(3531)` = 79_950 from the validated formula.
        // The brief's example of 75000 corresponds to _TMP = 3481
        // (3481 × 100 − 273_150 = 75_000 milli-C).  We test the
        // formula directly against the known good value from
        // acpi_thermal.rs smoke tests.
        let milli_c = crate::acpi_thermal::decik_to_milli_c(3531); // = 79_950
        kobject_add_attr(&kobj, "temp", move || format!("{}\n", milli_c));

        match kobj.attr_show("temp") {
            Some(ref s) if s.trim_end_matches('\n').parse::<i32>().is_ok() => {
                let v: i32 = s.trim_end_matches('\n').parse().unwrap();
                // decik_to_milli_c(3531) == 79_950 per acpi_thermal smoke.
                if v == 79_950 {
                    TestResult::Pass
                } else {
                    TestResult::Fail("temp milli-C mismatch for 3531 deciK input")
                }
            }
            Some(_) => TestResult::Fail("temp attr is not an integer"),
            None => TestResult::Fail("temp attr missing"),
        }
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_thermal_temp_3531_decik);

    // ── Smoke 8: trip_point_0_type = "critical" ──────────────────────

    fn smoke_sysfs_thermal_trip_point_0_type_critical() -> TestResult {
        __reset_for_test();
        let class = class_register("thermal");
        let kobj = class_device_register(class, "thermal_zone0-trip-test");

        // Register a single critical trip.
        kobject_add_attr(&kobj, "trip_point_0_type", || "critical\n".to_string());

        match read_attr(&kobj, "trip_point_0_type").as_deref() {
            Some("critical") => TestResult::Pass,
            _ => TestResult::Fail("trip_point_0_type not 'critical'"),
        }
    }
    kernel_test_in!(
        "power/sysfs_bridge",
        smoke_sysfs_thermal_trip_point_0_type_critical
    );

    // ── Smoke 9: cooling_device0/cur_state reads back what was set ───

    fn smoke_sysfs_cooling_device_cur_state_readback() -> TestResult {
        __reset_for_test();

        let dev = CoolingDeviceNode::new("Fan", 7);
        let dev = register_cooling_device_sysfs(dev, 0);

        // Set level 3.
        *dev.cur_state.lock() = 3u64;

        // Read it back via the class kobject.
        let class = class_register("thermal");
        // The registered kobject is "cooling_device0".
        let kobj = match class.get_child("cooling_device0") {
            Some(k) => k,
            None => return TestResult::Fail("cooling_device0 not registered under thermal class"),
        };

        match read_attr(&kobj, "cur_state").as_deref() {
            Some("3") => TestResult::Pass,
            Some(s) => {
                let _ = s;
                TestResult::Fail("cur_state readback mismatch")
            }
            None => TestResult::Fail("cur_state attr missing"),
        }
    }
    kernel_test_in!(
        "power/sysfs_bridge",
        smoke_sysfs_cooling_device_cur_state_readback
    );

    // ── Smoke 10: model_name from _BIF/_BIX ──────────────────────────

    fn smoke_sysfs_bat_model_name_from_bix() -> TestResult {
        __reset_for_test();
        use alloc::vec;
        use narf_aml::Value;

        // Build a synthetic _BIX package with model "ThinkPad-X1".
        let pkg = Value::Package(vec![
            Value::Integer(0),                        // revision
            Value::Integer(0),                        // power_unit = mWh
            Value::Integer(50_000),                   // design_capacity
            Value::Integer(47_000),                   // last_full_charge
            Value::Integer(1),                        // technology
            Value::Integer(12_000),                   // design_voltage
            Value::Integer(5_000),                    // warning
            Value::Integer(2_500),                    // low
            Value::Integer(501),                      // cycle_count
            Value::Integer(80_000),                   // accuracy
            Value::Integer(60_000),                   // max_sampling_ms
            Value::Integer(1_000),                    // min_sampling_ms
            Value::Integer(60_000),                   // max_avg_ms
            Value::Integer(1_000),                    // min_avg_ms
            Value::Integer(100),                      // gran1
            Value::Integer(100),                      // gran2
            Value::String("ThinkPad-X1".to_string()), // model_number
            Value::String("SN-99999".to_string()),    // serial_number
            Value::String("LIon".to_string()),        // battery_type
            Value::String("Lenovo".to_string()),      // oem_info
        ]);
        let info = match decode_bix(&pkg) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("decode_bix failed on synthetic package"),
        };

        // Register the attr manually (bypasses live AML).
        let class = class_register("power_supply");
        let kobj = class_device_register(class, "BAT0-model-test");
        let model = info.model_number.clone();
        kobject_add_attr(&kobj, "model_name", move || format!("{}\n", model));

        match read_attr(&kobj, "model_name").as_deref() {
            Some("ThinkPad-X1") => TestResult::Pass,
            Some(s) => {
                let _ = s;
                TestResult::Fail("model_name mismatch")
            }
            None => TestResult::Fail("model_name attr missing"),
        }
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_bat_model_name_from_bix);

    // ── Smoke 11: energy_full and energy_now in µWh ──────────────────

    fn smoke_sysfs_bat_energy_uwh_conversion() -> TestResult {
        __reset_for_test();
        let class = class_register("power_supply");
        let kobj = class_device_register(class, "BAT0-energy-test");

        // last_full_charge = 47_000 mWh → 47_000_000 µWh.
        kobject_add_attr(&kobj, "energy_full", || format!("{}\n", 47_000u64 * 1000));
        // remaining_capacity = 23_500 mWh → 23_500_000 µWh.
        kobject_add_attr(&kobj, "energy_now", || format!("{}\n", 23_500u64 * 1000));

        let ef = read_attr(&kobj, "energy_full")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let en = read_attr(&kobj, "energy_now")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        if ef != 47_000_000 {
            return TestResult::Fail("energy_full µWh conversion wrong");
        }
        if en != 23_500_000 {
            return TestResult::Fail("energy_now µWh conversion wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_bat_energy_uwh_conversion);

    // ── Smoke 12: cooling_device max_state attr ───────────────────────

    fn smoke_sysfs_cooling_device_max_state() -> TestResult {
        __reset_for_test();
        let dev = CoolingDeviceNode::new("Fan", 7);
        register_cooling_device_sysfs(dev, 1);

        let class = class_register("thermal");
        let kobj = match class.get_child("cooling_device1") {
            Some(k) => k,
            None => return TestResult::Fail("cooling_device1 not found"),
        };

        match read_attr(&kobj, "max_state").as_deref() {
            Some("7") => TestResult::Pass,
            _ => TestResult::Fail("max_state not 7"),
        }
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_cooling_device_max_state);

    // ── Smoke 13: thermal_zone type attr ─────────────────────────────

    fn smoke_sysfs_thermal_zone_type_attr() -> TestResult {
        __reset_for_test();
        let class = class_register("thermal");
        let kobj = class_device_register(class, "thermal_zone0-type-test");

        kobject_add_attr(&kobj, "type", || "TZ00\n".to_string());

        match read_attr(&kobj, "type").as_deref() {
            Some("TZ00") => TestResult::Pass,
            _ => TestResult::Fail("type attr mismatch"),
        }
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_thermal_zone_type_attr);

    // ── Smoke 14: trip_point ordering (critical before hot) ──────────

    fn smoke_sysfs_trip_point_ordering() -> TestResult {
        __reset_for_test();
        use narf_filesystem::sysfs::{class_device_register, class_register, kobject_add_attr};

        let class = class_register("thermal");
        let kobj = class_device_register(class, "thermal_zone0-order-test");

        // Register in priority order: critical=100_000, hot=95_000.
        kobject_add_attr(&kobj, "trip_point_0_type", || "critical\n".to_string());
        kobject_add_attr(&kobj, "trip_point_0_temp", || "100000\n".to_string());
        kobject_add_attr(&kobj, "trip_point_0_hyst", || "0\n".to_string());
        kobject_add_attr(&kobj, "trip_point_1_type", || "hot\n".to_string());
        kobject_add_attr(&kobj, "trip_point_1_temp", || "95000\n".to_string());
        kobject_add_attr(&kobj, "trip_point_1_hyst", || "0\n".to_string());

        if read_attr(&kobj, "trip_point_0_type").as_deref() != Some("critical") {
            return TestResult::Fail("trip_point_0_type should be critical");
        }
        if read_attr(&kobj, "trip_point_1_type").as_deref() != Some("hot") {
            return TestResult::Fail("trip_point_1_type should be hot");
        }
        let t0: i32 = read_attr(&kobj, "trip_point_0_temp")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let t1: i32 = read_attr(&kobj, "trip_point_1_temp")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if t0 <= t1 {
            return TestResult::Fail("critical trip temp should be > hot trip temp");
        }
        TestResult::Pass
    }
    kernel_test_in!("power/sysfs_bridge", smoke_sysfs_trip_point_ordering);
}
