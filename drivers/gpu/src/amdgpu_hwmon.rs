//! Generic amdgpu hwmon class device, shared by the discrete SMU owners
//! (Navi48 SMU14, Navi22 SMU11). Attribute names, labels and units follow
//! Linux amdgpu_pm.c (`hwmon_attributes`, `hwmon_attributes_visible` for a
//! SOC15 dGPU, and the `amdgpu_hwmon_show_*` scaling). Each generation maps
//! its last telemetry sample to a [`Reading`]; fan control stays automatic,
//! so every attribute here is read-only.
use alloc::{format, string::String, vec::Vec};

/// One snapshot in hwmon units' sources. `None` reads as an empty attribute
/// (an error to lm-sensors), never as a fake zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Reading {
    /// edge, junction (hotspot), mem; millidegrees Celsius.
    pub temp: [Option<i32>; 3],
    pub crit: [Option<i32>; 3],
    pub crit_hyst: [Option<i32>; 3],
    pub emergency: [Option<i32>; 3],
    /// 0-255 fan duty and tachometer RPM.
    pub pwm: Option<u8>,
    pub fan_rpm: Option<u16>,
    pub fan_max_rpm: Option<u16>,
    pub vddgfx_mv: Option<u16>,
    /// dGPU SoC rail, also exposed through INFO_SENSOR_VDDNB.
    pub vddsoc_mv: Option<u16>,
    /// Watts.
    pub power_average_w: Option<u32>,
    /// Latest SMU socket-power sample; firmware-averaged over its interval.
    pub power_input_w: Option<u32>,
    pub power_cap_w: Option<u32>,
    pub power_cap_default_w: Option<u32>,
    /// The settable `power1_cap` range, watts; None hides nothing but reads
    /// empty.
    pub power_cap_min_w: Option<u32>,
    pub power_cap_max_w: Option<u32>,
    /// MHz: sclk is the effective average GFXCLK, mclk the current UCLK.
    pub sclk_mhz: Option<u32>,
    pub mclk_mhz: Option<u32>,
}

/// Visible attribute names for a dGPU. `fan` hides every fan attribute when
/// the board has no PMFW fan control (`adev->pm.no_fan`). `rpm_mode` adds the
/// `fan1_target`/`fan1_enable` pair that SMU11 exposes (it has RPM setters);
/// SMU14 has none. Power input uses the latest firmware-averaged sample.
/// The overdrive-dependent `power1_cap_{min,max}` are added by their owner.
pub(crate) fn attributes(fan: bool, rpm_mode: bool) -> Vec<&'static str> {
    let mut names = Vec::new();
    for t in [
        [
            "temp1_input",
            "temp1_label",
            "temp1_crit",
            "temp1_crit_hyst",
            "temp1_emergency",
        ],
        [
            "temp2_input",
            "temp2_label",
            "temp2_crit",
            "temp2_crit_hyst",
            "temp2_emergency",
        ],
        [
            "temp3_input",
            "temp3_label",
            "temp3_crit",
            "temp3_crit_hyst",
            "temp3_emergency",
        ],
    ] {
        names.extend_from_slice(&t);
    }
    if fan {
        names.extend_from_slice(&[
            "pwm1",
            "pwm1_enable",
            "pwm1_min",
            "pwm1_max",
            "fan1_input",
            "fan1_min",
            "fan1_max",
        ]);
        if rpm_mode {
            names.extend_from_slice(&["fan1_target", "fan1_enable"]);
        }
    }
    names.extend_from_slice(&[
        "in0_input",
        "in0_label",
        "in1_input",
        "in1_label",
        "power1_average",
        "power1_input",
        "power1_cap",
        "power1_cap_default",
        "power1_label",
        "freq1_input",
        "freq1_label",
        "freq2_input",
        "freq2_label",
    ]);
    names
}

/// One attribute's sysfs text.
pub(crate) fn show(r: &Reading, name: &str) -> String {
    let index = |n: &str| match n.as_bytes().get(4) {
        Some(b'1') => Some(0),
        Some(b'2') => Some(1),
        Some(b'3') => Some(2),
        _ => None,
    };
    let value: Option<i64> = match name {
        "temp1_label" => return "edge\n".into(),
        "temp2_label" => return "junction\n".into(),
        "temp3_label" => return "mem\n".into(),
        "in0_label" => return "vddgfx\n".into(),
        "in1_label" => return "vddsoc\n".into(),
        "power1_label" => return "PPT\n".into(),
        "freq1_label" => return "sclk\n".into(),
        "freq2_label" => return "mclk\n".into(),
        // amdgpu_hwmon_get_pwm1_{min,max}; SMU reports MIN_FAN_RPM as zero;
        // automatic control is AMD_FAN_CTRL_AUTO: hwmon pwm mode 2 and
        // `fan1_enable` 0 (amdgpu_hwmon_get_fan1_enable).
        "pwm1_min" | "fan1_min" => Some(0),
        "pwm1_max" => Some(255),
        "pwm1_enable" => Some(2),
        "fan1_enable" => Some(0),
        n if n.starts_with("temp") => {
            let i = index(n);
            match (i, &n[5.min(n.len())..]) {
                (Some(i), "_input") => r.temp[i].map(Into::into),
                (Some(i), "_crit") => r.crit[i].map(Into::into),
                (Some(i), "_crit_hyst") => r.crit_hyst[i].map(Into::into),
                (Some(i), "_emergency") => r.emergency[i].map(Into::into),
                _ => None,
            }
        }
        "pwm1" => r.pwm.map(Into::into),
        // amdgpu_hwmon_get_fan1_target reads the same RPM sensor.
        "fan1_input" | "fan1_target" => r.fan_rpm.map(Into::into),
        "fan1_max" => r.fan_max_rpm.map(Into::into),
        "in0_input" => r.vddgfx_mv.map(Into::into),
        "in1_input" => r.vddsoc_mv.map(Into::into),
        // Microwatts, from PMFW watts.
        "power1_average" => r.power_average_w.map(|w| i64::from(w) * 1_000_000),
        "power1_input" => r.power_input_w.map(|w| i64::from(w) * 1_000_000),
        "power1_cap" => r.power_cap_w.map(|w| i64::from(w) * 1_000_000),
        "power1_cap_default" => r.power_cap_default_w.map(|w| i64::from(w) * 1_000_000),
        "power1_cap_min" => r.power_cap_min_w.map(|w| i64::from(w) * 1_000_000),
        "power1_cap_max" => r.power_cap_max_w.map(|w| i64::from(w) * 1_000_000),
        // Hz (amdgpu_hwmon_show_sclk/mclk: 10 kHz sensor units * 10 * 1000).
        "freq1_input" => r.sclk_mhz.map(|m| i64::from(m) * 1_000_000),
        "freq2_input" => r.mclk_mhz.map(|m| i64::from(m) * 1_000_000),
        _ => None,
    };
    value.map_or_else(String::new, |v| format!("{v}\n"))
}

/// Publish `/sys/class/hwmon/hwmon<N>` (first free N) named `amdgpu`, each
/// attribute rendered on read by `show`.
pub(crate) fn publish(names: Vec<&'static str>, show: fn(&'static str) -> String) {
    publish_writable(names, show, &[], |_, _| {
        Err(narf_filesystem::FsError::OperationNotPermitted)
    });
}

/// [`publish`] with `writable` attributes stored through `store`
/// (`S_IRUGO | S_IWUSR` in amdgpu_pm.c), which gets the raw written bytes.
pub(crate) fn publish_writable(
    names: Vec<&'static str>,
    show: fn(&'static str) -> String,
    writable: &[&'static str],
    store: fn(&'static str, &[u8]) -> Result<(), narf_filesystem::FsError>,
) {
    use narf_filesystem::sysfs::{
        class_device_register, class_register, kobject_add_attr, kobject_add_writable_attr,
    };
    let class = class_register("hwmon");
    let taken = class.child_names();
    let index = (0..).find(|i| !taken.iter().any(|n| *n == format!("hwmon{i}")));
    let Some(index) = index else { return };
    let node = class_device_register(class, &format!("hwmon{index}"));
    kobject_add_attr(&node, "name", || "amdgpu\n".into());
    // Linux hwmon class devices have no device node, so no DEVNAME/MAJOR.
    narf_filesystem::sysfs::kobject_add_uevent_attr(&node, String::new());
    for name in names {
        if writable.contains(&name) {
            kobject_add_writable_attr(&node, name, move || show(name), move |b| store(name, b));
        } else {
            kobject_add_attr(&node, name, move || show(name));
        }
    }
}

/// `kstrtou32(buf, 10)` as sysfs stores parse it: decimal, optional
/// trailing newline.
pub(crate) fn parse_u32(bytes: &[u8]) -> Option<u32> {
    let text = core::str::from_utf8(bytes).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}
