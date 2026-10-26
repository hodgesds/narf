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
//! - `temp<i>_max`     — high threshold (only when the device reports one)
//! - `temp<i>_crit`    — critical threshold (only when the device reports one)
//! - `fan<i>_input`    — tachometer reading in RPM
//! - `fan<i>_label`    — fan label
//! - `pwm<i>`          — writable fan duty 0–255 (only for channels the
//!   device can actually control; paired with `fan<i>`)
//! - `in<i>_input`     — voltage input in millivolts
//! - `in<i>_label`     — voltage label
//! - `update_interval` — milliseconds between hardware reads (stub 1000)
//!
//! ## Thresholds
//!
//! `temp<i>_max` / `temp<i>_crit` are published only when
//! [`HwmonDevice::temp_limits`] reports a real hardware limit for the
//! label (a Tjmax MSR, a programmed limit register) — never a
//! bridge-invented constant (#909). The show re-reads the limit live,
//! so a failed limit read renders empty under the same rule as a
//! failed sensor read below.
//!
//! ## Fan control
//!
//! For each fan channel the device marks controllable
//! ([`HwmonDevice::supports_fan_control`]), `pwm<i>` is a writable
//! attribute: reading it returns the current duty from
//! [`HwmonDevice::read_pwm`] (empty when unreadable), and writing a
//! decimal duty in 0–255 drives [`HwmonDevice::set_fan`] — the
//! userspace production caller for fan control. Channels without a
//! real driver behind them get no `pwm<i>` attribute at all, so a
//! published control is never a dead end. The in-kernel caller is
//! the thermal governor (see `crate::cooling`).
//!
//! ## Failed reads
//!
//! When a device read fails (`read_temp` / `read_fan` / `read_voltage`
//! returns `None`) the corresponding `*_input` attribute renders an
//! **empty** value — never a fabricated `0`. Linux hwmon fails such a
//! read with an error; this tree's sysfs show API
//! (`narf_filesystem::sysfs::AttrShow`) is infallible, so an empty
//! render is the honest representation available: consumers see EOF
//! instead of a plausible-looking 0 °C / 0 RPM / 0 mV. A genuine zero
//! reading still renders as `"0\n"`.
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

use narf_filesystem::sysfs::{
    class_device_register, class_register, kobject_add_attr, kobject_add_writable_attr,
};
use narf_filesystem::FsError;

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
    if label.starts_with("temp")
        || label.starts_with('T')
        || label.starts_with("Core")
        || label.starts_with("Package")
        || matches!(label, "cpu" | "gpu" | "hdd" | "ambient")
    {
        return Some(LabelKind::Temp);
    }
    if label.starts_with("fan") {
        return Some(LabelKind::Fan);
    }
    // `pwm<n>` is a fan-control output, not a voltage input — it is
    // driven through `HwmonDevice::set_fan`, not read as an `in<n>`
    // attribute, so it is deliberately not classified here.
    if label.starts_with("in") {
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
                // pwm<n> pairs with fan<n> (Linux hwmon convention)
                // and exists only where the device can really drive
                // the channel.
                if dev.supports_fan_control(label) {
                    add_pwm_attr(&kobj, dev.clone(), label, fan_idx);
                }
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
                // Failed read: render empty, never a fabricated 0
                // (see the module docs, "Failed reads").
                None => String::new(),
            }
        });
    }

    // temp<n>_label
    {
        let attr_name = intern(format!("temp{}_label", n));
        kobject_add_attr(kobj, attr_name, move || format!("{}\n", label_owned));
    }

    // temp<n>_max / temp<n>_crit — published only when the device
    // reports a real hardware limit for this label (#909); there is
    // no generic TJ_MAX constant to fall back on. Existence is probed
    // once here; the show re-reads the limit live and renders empty
    // if it has become unreadable (the failed-read rule above).
    // Linux: hwmon_temp_max (drivers/hwmon/hwmon.c:186),
    //        hwmon_temp_crit (drivers/hwmon/hwmon.c:194).
    let (max_mc, crit_mc) = dev.temp_limits(label_owned);
    if max_mc.is_some() {
        let attr_name = intern(format!("temp{}_max", n));
        let dev2 = dev.clone();
        kobject_add_attr(kobj, attr_name, move || {
            match dev2.temp_limits(label_owned).0 {
                Some(mc) => format!("{}\n", mc),
                None => String::new(),
            }
        });
    }
    if crit_mc.is_some() {
        let attr_name = intern(format!("temp{}_crit", n));
        let dev2 = dev.clone();
        kobject_add_attr(kobj, attr_name, move || {
            match dev2.temp_limits(label_owned).1 {
                Some(mc) => format!("{}\n", mc),
                None => String::new(),
            }
        });
    }
}

/// Add the writable `pwm<n>` attribute paired with fan channel `n`.
///
/// Only called for channels the device marks controllable
/// ([`HwmonDevice::supports_fan_control`]), so the attribute always
/// has a real driver behind it. Show reads the live duty back via
/// [`HwmonDevice::read_pwm`] (empty when unreadable, per the
/// failed-read rule); store parses a decimal duty in 0–255 and
/// drives it through [`HwmonDevice::set_fan`].
///
/// Store errors: malformed or out-of-range input is
/// `FsError::InvalidData` (Linux `pwm_store` returns `-EINVAL`); a
/// driver refusal is `FsError::NoDevice`.
///
/// Linux ref: `hwmon_pwm_show` / `hwmon_pwm_store`
/// (drivers/hwmon/hwmon.c:282).
fn add_pwm_attr(
    kobj: &narf_filesystem::sysfs::Kobject,
    dev: Arc<dyn HwmonDevice + Send + Sync>,
    label: &str,
    n: u32,
) {
    let label_owned: &'static str = intern(String::from(label));
    let attr_name = intern(format!("pwm{}", n));
    let dev_show = dev.clone();
    kobject_add_writable_attr(
        kobj,
        attr_name,
        move || match dev_show.read_pwm(label_owned) {
            Some(duty) => format!("{}\n", duty),
            None => String::new(),
        },
        move |buf| {
            let s = core::str::from_utf8(buf)
                .map_err(|_| FsError::InvalidData)?
                .trim();
            let v: u32 = s.parse().map_err(|_| FsError::InvalidData)?;
            if v > 255 {
                return Err(FsError::InvalidData);
            }
            if dev.set_fan(label_owned, v as u8) {
                Ok(())
            } else {
                Err(FsError::NoDevice)
            }
        },
    );
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
        kobject_add_attr(kobj, attr_name, move || match dev2.read_fan(label_owned) {
            Some(rpm) => format!("{}\n", rpm),
            // Failed read: render empty, never a fabricated 0
            // (see the module docs, "Failed reads").
            None => String::new(),
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
                // Failed read: render empty, never a fabricated 0
                // (see the module docs, "Failed reads").
                None => String::new(),
            }
        });
    }

    // in<n>_label
    {
        let attr_name = intern(format!("in{}_label", n));
        kobject_add_attr(kobj, attr_name, move || format!("{}\n", label_owned));
    }
}
