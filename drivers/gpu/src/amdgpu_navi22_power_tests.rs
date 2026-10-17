use super::*;
use crate::amdgpu_smu_navi22_telemetry::{Layout, Metrics};
use narf_kernel_test::{kernel_test_in, TestResult};

fn limits(fan: bool) -> Limits {
    Limits {
        edge_crit_milli: 100_000,
        edge_emergency_milli: 105_000,
        hotspot_crit_milli: 110_000,
        hotspot_emergency_milli: 115_000,
        mem_crit_milli: 100_000,
        mem_emergency_milli: 105_000,
        software_shutdown_c: 118,
        fan_max_rpm: fan.then_some(3300),
        ppt_table_w: 203,
        thermal_controller: 0x13,
        dc_by_gpio: false,
    }
}
fn telemetry(hotspot_c: i32, throttlers: u32) -> Telemetry {
    Telemetry {
        layout: Layout::V2,
        metrics: Metrics {
            edge_milli: 52_000,
            hotspot_milli: hotspot_c * 1000,
            mem_milli: 60_000,
            fan_rpm: 1450,
            socket_power_w: 171,
            gfx_mhz: 2554,
            uclk_mhz: 1000,
            throttlers,
            ..Metrics::default()
        },
        enabled: 0,
        ppt_limit_w: 186,
        vddgfx_mv: 1150,
        fan_pwm: Some(96),
    }
}
fn sample(telemetry: Result<Telemetry, smu::Error>, protected: bool) -> Sample {
    Sample {
        telemetry,
        limits: Some(limits(true)),
        protected,
    }
}

fn navi22_power_snapshot_reports_transitions_once() -> TestResult {
    let (s, e) = update(None, sample(Ok(telemetry(70, 1 << 13)), true));
    if e.started != 1 << 13 || e.protection_lost || e.software_shutdown || s.samples != 1 {
        return TestResult::Fail("first sample events");
    }
    if s.ppt_default_w != Some(186) {
        return TestResult::Fail("default power limit not captured from PMFW");
    }
    let mut lowered = telemetry(70, 0);
    lowered.ppt_limit_w = 150;
    let (s, e) = update(Some(s), sample(Ok(lowered), true));
    if e.stopped != 1 << 13 || e.started != 0 || s.ppt_default_w != Some(186) {
        return TestResult::Fail("throttling end / default limit kept");
    }
    let (s, e) = update(Some(s), sample(Ok(telemetry(118, 0)), true));
    if !e.software_shutdown {
        return TestResult::Fail("software shutdown temperature not reported");
    }
    let (s, e) = update(Some(s), sample(Ok(telemetry(119, 0)), false));
    if e.software_shutdown || !e.protection_lost {
        return TestResult::Fail("repeated emergency / protection loss");
    }
    let (s, e) = update(Some(s), sample(Err(smu::Error::Rejected(0xfe)), true));
    if e.failed != Some(smu::Error::Rejected(0xfe))
        || s.telemetry != Some(telemetry(119, 0))
        || s.protected
        || s.samples != 4
    {
        return TestResult::Fail("failed refresh must retain the last sample");
    }
    let (_, e) = update(Some(s), sample(Err(smu::Error::Timeout), true));
    if e.failed.is_some() {
        return TestResult::Fail("repeated failure reported twice");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-power",
    navi22_power_snapshot_reports_transitions_once
);

fn navi22_hwmon_follows_linux_amdgpu_units_and_visibility() -> TestResult {
    let names = attributes(true);
    if names.len() != 34 || !names.contains(&"fan1_target") || !names.contains(&"fan1_enable") {
        return TestResult::Fail("SMU11 fan attributes");
    }
    if attributes(false)
        .iter()
        .any(|n| n.starts_with("pwm") || n.starts_with("fan"))
    {
        return TestResult::Fail("fanless board exposes fan attributes");
    }
    let mut s = Snapshot {
        telemetry: None,
        limits: None,
        protected: false,
        ppt_default_w: None,
        error: None,
        samples: 0,
    };
    for name in [
        "temp1_input",
        "temp2_crit",
        "power1_cap",
        "fan1_max",
        "pwm1",
    ] {
        if !show(Some(&s), name).is_empty() {
            return TestResult::Fail("fake value before data");
        }
    }
    s.limits = Some(limits(true));
    if show(Some(&s), "power1_cap_default") != "203000000\n" {
        return TestResult::Fail("table AC limit fallback");
    }
    s.telemetry = Some(telemetry(77, 0));
    s.ppt_default_w = Some(186);
    for (name, value) in [
        ("temp1_input", "52000\n"),
        ("temp2_input", "77000\n"),
        ("temp3_input", "60000\n"),
        ("temp2_label", "junction\n"),
        ("temp1_crit", "100000\n"),
        ("temp2_crit", "110000\n"),
        ("temp3_crit_hyst", "-273150\n"),
        ("temp2_emergency", "115000\n"),
        ("pwm1", "96\n"),
        ("pwm1_enable", "2\n"),
        ("fan1_input", "1450\n"),
        ("fan1_target", "1450\n"),
        ("fan1_enable", "0\n"),
        ("fan1_max", "3300\n"),
        ("in0_input", "1150\n"),
        ("power1_average", "171000000\n"),
        ("power1_cap", "186000000\n"),
        ("power1_cap_default", "186000000\n"),
        ("freq1_input", "2554000000\n"),
        ("freq2_input", "1000000000\n"),
        ("power1_input", ""),
    ] {
        if show(Some(&s), name) != value {
            return TestResult::Fail("hwmon value or unit");
        }
    }
    for name in &names {
        if show(Some(&s), name).is_empty() {
            return TestResult::Fail("visible attribute without a value");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-power",
    navi22_hwmon_follows_linux_amdgpu_units_and_visibility
);
