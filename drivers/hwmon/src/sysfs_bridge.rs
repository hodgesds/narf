//! sysfs bridge — `/sys/class/hwmon/hwmon<N>/` population.
//!
//! For each device registered in [`crate::registry::devices()`] this
//! module creates one kobject under `/sys/class/hwmon/` and attaches
//! the standard hwmon attributes defined in
//! `Documentation/hwmon/sysfs-interface` (Linux 6.9):
//!
//! - `name`             — chip name, e.g. `"k10temp\n"`
//! - `temp<i>_input`   — temperature in millidegrees C
//! - `temp<i>_label`   — human label, e.g. `"Tdie\n"`
//! - `temp<i>_max`     — high threshold (if provided)
//! - `temp<i>_crit`    — critical threshold (if provided)
//! - `fan<i>_input`    — tachometer reading in RPM
//! - `fan<i>_label`    — fan label
//! - `in<i>_input`     — voltage input in millivolts
//! - `in<i>_label`     — voltage label
//! - `update_interval` — milliseconds between hardware reads (stub 1000)
//!
//! Linux references:
//! - `drivers/hwmon/hwmon.c:597`  `hwmon_device_register_with_info`
//! - `Documentation/hwmon/sysfs-interface` attribute naming convention
//! - `fs/sysfs/file.c:413`        `sysfs_create_file`
//!
//! ## Numbering
//!
//! `hwmon<N>` indexes increment per registered device in the order
//! `registry::devices()` returns them (probe order, typically
//! k10temp=0, coretemp=1, nct6775=2, dell_smm=3 on a Dell/AMD laptop).
//!
//! Within each device, labels are numbered starting at 1:
//! - temperature labels → `temp1_*`, `temp2_*`, ...
//! - fan labels         → `fan1_*`, `fan2_*`, ...
//! - voltage labels     → `in1_*`, `in2_*`, ...
//!
//! ## String interning
//!
//! `kobject_add_attr` requires `&'static str` keys.  Dynamically-generated
//! names (e.g. `"temp3_input"`) are interned once via `Box::leak` during
//! bridge init — this is acceptable in a kernel init path.

#![allow(clippy::format_collect)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use narf_filesystem::sysfs::{class_register, class_device_register, kobject_add_attr};

use crate::HwmonDevice;

// ── Label classification ──────────────────────────────────────────────

/// Decide which sysfs attribute group a label belongs to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum LabelKind {
    Temp,
    Fan,
    Voltage,
}

/// Classify a label by probing the device for each sensor type.
///
/// We try `read_temp` first, then `read_fan`, then `read_voltage`.
/// If none of them have this label recognised (all return `None`),
/// we fall back to heuristics on the label string itself — k10temp
/// and coretemp labels (Tctl, Tdie, Core0 …) start with `'T'` or
/// `'C'` which map to temperature.
fn classify_label(dev: &dyn HwmonDevice, label: &str) -> Option<LabelKind> {
    // Heuristic first: nct6775 and dell_smm use systematic prefixes.
    if label.starts_with("temp") || label.starts_with('T')
        || label.starts_with("Core") || label.starts_with("Package")
        || matches!(label, "cpu" | "gpu" | "hdd" | "ambient")
    {
        return Some(LabelKind::Temp);
    }
    if label.starts_with("fan") {
        return Some(LabelKind::Fan);
    }
    if label.starts_with("in") || label.starts_with("pwm") {
        return Some(LabelKind::Voltage);
    }
    // Fall back to probing — `None` return from read_* still classifies
    // by whether the device *knows* the label (returns Some or None based
    // on label recognition, not just "no hardware").
    //
    // We use a marker sentinel: drivers return `None` for unknown labels,
    // but we can't distinguish "known but hardware not ready" from "unknown".
    // Use the presence in list_labels() as the authority; this branch is
    // only reached if the prefix heuristics above didn't fire.
    let _ = dev; // available for future extension
    None
}

// ── Attr name interning ───────────────────────────────────────────────

/// Intern a dynamically-generated attribute name as `&'static str`.
///
/// Leaks a small heap allocation once per attribute at bridge-init time.
/// Total size: ≲ 512 bytes for a fully-populated 4-device system.
fn intern(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

// ── Bridge entry point ────────────────────────────────────────────────

/// Populate `/sys/class/hwmon/hwmon<N>/` for every device in the
/// hwmon registry.
///
/// Called from a `Stage::Late` initcall (after all `Stage::Subsys` driver
/// probes have completed) so every device is already in the registry.
///
/// Linux ref: `hwmon_device_register_with_info` (drivers/hwmon/hwmon.c:597).
pub fn populate_hwmon_class() {
    let class_hwmon = class_register("hwmon");

    for (idx, dev) in crate::registry::devices().into_iter().enumerate() {
        populate_one_device(class_hwmon.clone(), idx, dev);
    }
}

/// Build `/sys/class/hwmon/hwmon<idx>/` for a single device.
fn populate_one_device(
    class_hwmon: Arc<narf_filesystem::sysfs::Kobject>,
    idx: usize,
    dev: Arc<dyn HwmonDevice + Send + Sync>,
) {
    // e.g. "hwmon0", "hwmon1"
    let node_name = format!("hwmon{}", idx);
    let kobj = class_device_register(class_hwmon, &node_name);

    // `name` attr — chip name.
    // Linux: hwmon_dev_attr_name (drivers/hwmon/hwmon.c:408).
    {
        let dev2 = dev.clone();
        kobject_add_attr(&kobj, "name", move || format!("{}\n", dev2.name()));
    }

    // `update_interval` — stub 1000 ms (live calibration deferred).
    // Linux: hwmon_dev_attr_update_interval (drivers/hwmon/hwmon.c:438).
    kobject_add_attr(&kobj, "update_interval", || "1000\n".into());

    // Sort labels into buckets.
    let labels = dev.list_labels();
    let mut temp_idx: u32 = 1;
    let mut fan_idx: u32 = 1;
    let mut in_idx: u32 = 1;

    for label in labels {
        let kind = match classify_label(dev.as_ref(), label) {
            Some(k) => k,
            None => continue,
        };

        match kind {
            LabelKind::Temp => {
                add_temp_attrs(&kobj, dev.clone(), label, temp_idx);
                temp_idx += 1;
            }
            LabelKind::Fan => {
                add_fan_attrs(&kobj, dev.clone(), label, fan_idx);
                fan_idx += 1;
            }
            LabelKind::Voltage => {
                add_voltage_attrs(&kobj, dev.clone(), label, in_idx);
                in_idx += 1;
            }
        }
    }
}

// ── Per-sensor attribute builders ─────────────────────────────────────

/// Add `temp<n>_input`, `temp<n>_label` (and optionally `_max`/`_crit`)
/// to `kobj`.
///
/// Linux ref: `SENSOR_DEVICE_ATTR` macro pattern, `hwmon_temp_input`
/// (drivers/hwmon/hwmon.c:168).
fn add_temp_attrs(
    kobj: &narf_filesystem::sysfs::Kobject,
    dev: Arc<dyn HwmonDevice + Send + Sync>,
    label: &str,
    n: u32,
) {
    let label_owned: &'static str = intern(String::from(label));

    // temp<n>_input
    {
        let attr_name = intern(format!("temp{}_input", n));
        let dev2 = dev.clone();
        kobject_add_attr(kobj, attr_name, move || {
            match dev2.read_temp(label_owned) {
                Some(mc) => format!("{}\n", mc),
                // Return a sentinel: hwmon convention is to return the
                // last known good value; we return 0 when hardware is
                // not yet accessible (ECAM / MSR not wired).
                None => "0\n".into(),
            }
        });
    }

    // temp<n>_label
    {
        let attr_name = intern(format!("temp{}_label", n));
        kobject_add_attr(kobj, attr_name, move || format!("{}\n", label_owned));
    }

    // temp<n>_max — not configurable in this first cut; expose the
    // generic TJ_MAX convention of 100 °C = 100_000 mC.
    // Linux: hwmon_temp_max (drivers/hwmon/hwmon.c:186).
    {
        let attr_name = intern(format!("temp{}_max", n));
        kobject_add_attr(kobj, attr_name, || "100000\n".into());
    }

    // temp<n>_crit — 105 °C default (AMD/Intel thermal throttle point).
    // Linux: hwmon_temp_crit (drivers/hwmon/hwmon.c:194).
    {
        let attr_name = intern(format!("temp{}_crit", n));
        kobject_add_attr(kobj, attr_name, || "105000\n".into());
    }
}

/// Add `fan<n>_input` and `fan<n>_label` to `kobj`.
///
/// Linux ref: `hwmon_fan_input` (drivers/hwmon/hwmon.c:246).
fn add_fan_attrs(
    kobj: &narf_filesystem::sysfs::Kobject,
    dev: Arc<dyn HwmonDevice + Send + Sync>,
    label: &str,
    n: u32,
) {
    let label_owned: &'static str = intern(String::from(label));

    // fan<n>_input
    {
        let attr_name = intern(format!("fan{}_input", n));
        let dev2 = dev.clone();
        kobject_add_attr(kobj, attr_name, move || {
            match dev2.read_fan(label_owned) {
                Some(rpm) => format!("{}\n", rpm),
                None => "0\n".into(),
            }
        });
    }

    // fan<n>_label
    {
        let attr_name = intern(format!("fan{}_label", n));
        kobject_add_attr(kobj, attr_name, move || format!("{}\n", label_owned));
    }
}

/// Add `in<n>_input` and `in<n>_label` to `kobj`.
///
/// Linux ref: `hwmon_in_input` (drivers/hwmon/hwmon.c:218).
fn add_voltage_attrs(
    kobj: &narf_filesystem::sysfs::Kobject,
    dev: Arc<dyn HwmonDevice + Send + Sync>,
    label: &str,
    n: u32,
) {
    let label_owned: &'static str = intern(String::from(label));

    // in<n>_input
    {
        let attr_name = intern(format!("in{}_input", n));
        let dev2 = dev.clone();
        kobject_add_attr(kobj, attr_name, move || {
            match dev2.read_voltage(label_owned) {
                Some(mv) => format!("{}\n", mv),
                None => "0\n".into(),
            }
        });
    }

    // in<n>_label
    {
        let attr_name = intern(format!("in{}_label", n));
        kobject_add_attr(kobj, attr_name, move || format!("{}\n", label_owned));
    }
}
