use super::*;
use crate::amdgpu_smu_navi48_telemetry::Metrics;
use narf_kernel_test::{kernel_test_in, TestResult};

fn limits(fan: bool) -> Limits {
    Limits {
        edge_crit_milli: 100_000,
        edge_emergency_milli: 105_000,
        hotspot_crit_milli: 110_000,
        hotspot_emergency_milli: 115_000,
        mem_crit_milli: 108_000,
        mem_emergency_milli: 113_000,
        software_shutdown_c: 118,
        software_shutdown_offset_c: -10,
        fan_max_rpm: fan.then_some(3300),
        ppt_default_w: 304,
    }
}
fn telemetry(hotspot_c: i32, throttlers: u32) -> Telemetry {
    Telemetry {
        metrics: Metrics {
            counter: 7,
            edge_milli: 61_000,
            hotspot_milli: hotspot_c * 1000,
            mem_milli: 70_000,
            fan_rpm: 1620,
            fan_pwm: 127,
            socket_power_w: 287,
            vddgfx_mv: 1050,
            gfx_mhz: 2450,
            uclk_mhz: 1258,
            throttlers,
            ..Metrics::default()
        },
        enabled: 0x3e80_0000,
        ppt_limit_w: 304,
    }
}
fn sample(telemetry: Result<Telemetry, smu::Error>, protected: bool) -> Sample {
    Sample {
        telemetry,
        limits: Some(limits(true)),
        protected,
        gfx_level: smu::GfxLevel::Auto,
    }
}

fn navi48_power_snapshot_reports_transitions_once() -> TestResult {
    let seed = Snapshot {
        telemetry: None,
        limits: Some(limits(true)),
        protected: false,
        gfx_level: smu::GfxLevel::Auto,
        error: None,
        samples: 0,
    };
    let (s, e) = update(Some(seed), sample(Ok(telemetry(77, 1 << 14)), true));
    assert_eq!(e.started, 1 << 14);
    assert!(!e.protection_lost && !e.software_shutdown && e.failed.is_none());
    assert!(s.protected && s.samples == 1 && s.error.is_none());
    // Same throttler again: no event. A new one plus one ending.
    let (s, e) = update(Some(s), sample(Ok(telemetry(77, 1 << 14)), true));
    assert_eq!(e, Events::default());
    let (s, e) = update(Some(s), sample(Ok(telemetry(77, 1 << 1)), true));
    assert_eq!((e.started, e.stopped), (1 << 1, 1 << 14));
    // Software shutdown temperature reported on entry only.
    let (s, e) = update(Some(s), sample(Ok(telemetry(118, 0)), true));
    assert!(e.software_shutdown);
    let (s, e) = update(Some(s), sample(Ok(telemetry(119, 0)), true));
    assert!(!e.software_shutdown);
    // Lost protection reported once; a failed refresh keeps the last sample.
    let (s, e) = update(Some(s), sample(Ok(telemetry(60, 0)), false));
    assert!(e.protection_lost && !s.protected);
    let (s, e) = update(Some(s), sample(Ok(telemetry(60, 0)), false));
    assert!(!e.protection_lost);
    let (s, e) = update(Some(s), sample(Err(smu::Error::Rejected(0xfc)), false));
    assert_eq!(e.failed, Some(smu::Error::Rejected(0xfc)));
    assert_eq!(s.telemetry, Some(telemetry(60, 0)));
    assert_eq!((s.error, s.samples), (Some(smu::Error::Rejected(0xfc)), 7));
    let (s, e) = update(Some(s), sample(Err(smu::Error::Rejected(0xfc)), false));
    assert!(e.failed.is_none() && s.error.is_some());
    // Lost protection on the very first sample is reported too.
    let (_, e) = update(Some(seed), sample(Ok(telemetry(60, 0)), false));
    assert!(e.protection_lost);
    assert_eq!(throttler_names((1 << 1) | (1 << 14)), "temp-hotspot,ppt0");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_power_snapshot_reports_transitions_once
);

fn navi48_hwmon_follows_linux_amdgpu_units_and_visibility() -> TestResult {
    let names = attributes(true);
    assert_eq!(names.len(), 32);
    assert!(names.contains(&"pwm1") && names.contains(&"fan1_max"));
    let fanless = attributes(false);
    assert!(!fanless
        .iter()
        .any(|n| n.starts_with("pwm") || n.starts_with("fan")));
    let mut s = Snapshot {
        telemetry: None,
        limits: None,
        protected: false,
        gfx_level: smu::GfxLevel::Auto,
        error: None,
        samples: 0,
    };
    // No fake zeroes before data exists; labels and fixed ranges are static.
    for name in [
        "temp1_input",
        "temp1_crit",
        "power1_cap",
        "fan1_max",
        "freq1_input",
    ] {
        assert_eq!(show(Some(&s), name), "");
    }
    assert_eq!(show(None, "temp2_label"), "junction\n");
    assert_eq!(show(None, "pwm1_enable"), "2\n");
    assert_eq!(show(None, "pwm1_max"), "255\n");
    s.telemetry = Some(telemetry(77, 0));
    s.limits = Some(limits(true));
    for (name, value) in [
        ("temp1_input", "61000\n"),
        ("temp2_input", "77000\n"),
        ("temp3_input", "70000\n"),
        ("temp1_crit", "100000\n"),
        ("temp2_crit", "110000\n"),
        ("temp3_crit", "108000\n"),
        ("temp1_crit_hyst", "-273150\n"),
        ("temp2_emergency", "115000\n"),
        ("temp3_emergency", "113000\n"),
        ("temp1_label", "edge\n"),
        ("temp3_label", "mem\n"),
        ("pwm1", "127\n"),
        ("fan1_input", "1620\n"),
        ("fan1_min", "0\n"),
        ("fan1_max", "3300\n"),
        ("in0_input", "1050\n"),
        ("in0_label", "vddgfx\n"),
        ("power1_average", "287000000\n"),
        ("power1_cap", "304000000\n"),
        ("power1_cap_default", "304000000\n"),
        ("power1_label", "PPT\n"),
        ("freq1_input", "2450000000\n"),
        ("freq1_label", "sclk\n"),
        ("freq2_input", "1258000000\n"),
        ("freq2_label", "mclk\n"),
        ("unknown", ""),
    ] {
        assert_eq!(show(Some(&s), name), value, "{name}");
    }
    for name in &names {
        assert!(!show(Some(&s), name).is_empty(), "{name}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_hwmon_follows_linux_amdgpu_units_and_visibility
);

fn navi48_hwmon_publishes_next_free_class_node() -> TestResult {
    use narf_filesystem::sysfs::{class_device_register, class_register};
    let class = class_register("hwmon");
    let before = class.child_names();
    // Occupy the next index so publication must skip it.
    let next = (0..)
        .find(|i| !before.iter().any(|n| *n == format!("hwmon{i}")))
        .unwrap();
    class_device_register(class.clone(), &format!("hwmon{next}"));
    publish(Some(limits(false)));
    let node = class.get_child(&format!("hwmon{}", next + 1)).unwrap();
    assert_eq!(node.attr_show("name").as_deref(), Some("amdgpu\n"));
    assert_eq!(node.attr_show("temp1_label").as_deref(), Some("edge\n"));
    assert!(node.has_attr("power1_average") && !node.has_attr("pwm1"));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-power",
    navi48_hwmon_publishes_next_free_class_node
);
