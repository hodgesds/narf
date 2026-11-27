use super::*;
use crate::amdgpu_smu_navi31_telemetry::{Limits, Metrics, Telemetry};
use narf_kernel_test::{kernel_test_in, TestResult};

fn limits() -> Limits {
    Limits {
        edge_crit_milli: 100_000,
        edge_emergency_milli: 105_000,
        hotspot_crit_milli: 110_000,
        hotspot_emergency_milli: 115_000,
        mem_crit_milli: 108_000,
        mem_emergency_milli: 113_000,
        software_shutdown_c: 118,
        software_shutdown_offset_c: -10,
        fan_max_rpm: Some(3300),
        ppt_default_w: 304,
        ppt_min_w: 273,
        ppt_max_w: 340,
    }
}
fn telemetry(edge_milli: i32, hotspot_milli: i32, throttlers: u32) -> Telemetry {
    Telemetry {
        metrics: Metrics {
            edge_milli,
            hotspot_milli,
            mem_milli: 58_000,
            vr_gfx_milli: 49_000,
            vr_soc_milli: 44_000,
            fan_rpm: 1350,
            fan_pwm: 114,
            socket_power_w: 186,
            board_power_w: 210,
            vddgfx_mv: 1050,
            vddsoc_mv: Some(950),
            gfx_mhz: 600,
            fclk_mhz: 1500,
            mem_mhz: 1000,
            uclk_mhz: 2000,
            gfx_activity: 10,
            mem_activity: 7,
            throttlers,
            pcie_rate: 3,
            pcie_width: 16,
            ..Metrics::default()
        },
        enabled: crate::amdgpu_smu_navi31_telemetry::PROTECTION,
        ppt_limit_w: 300,
    }
}
fn sample(t: Result<Telemetry, RefreshError>, limits: Option<Limits>) -> Sample {
    Sample {
        telemetry: t,
        limits,
        protected: t.is_ok(),
    }
}

fn navi31_power_update_folds_samples_and_reports_transitions() -> TestResult {
    let (s, e) = update(
        None,
        sample(Ok(telemetry(51_000, 63_000, 0)), Some(limits())),
    );
    assert_eq!(s.samples, 1);
    assert!(s.telemetry.is_some());
    assert!(s.protected);
    assert_eq!(e, Events::default());
    let (s, e) = update(
        Some(s),
        sample(Ok(telemetry(51_000, 63_000, 1 << 16)), Some(limits())),
    );
    assert_eq!(s.samples, 2);
    assert_eq!(e.started, 1 << 16);
    assert_eq!(e.stopped, 0);
    assert!(!e.protection_lost);
    let (s, e) = update(
        Some(s),
        sample(Ok(telemetry(51_000, 63_000, 0)), Some(limits())),
    );
    assert_eq!(e.started, 0);
    assert_eq!(e.stopped, 1 << 16);
    // A failed refresh keeps the last sample and reports the first failure.
    let (s, e) = update(
        Some(s),
        sample(Err(RefreshError::DeviceGone), Some(limits())),
    );
    assert!(s.telemetry.is_some());
    assert_eq!(s.samples, 3);
    assert_eq!(e.failed, Some(RefreshError::DeviceGone));
    let (s, e) = update(
        Some(s),
        sample(Err(RefreshError::Rejected(0xfe)), Some(limits())),
    );
    assert_eq!(e.failed, None);
    assert!(s.protected);
    // Hotspot at the software shutdown temperature trips once.
    let (s, e) = update(
        Some(s),
        sample(Ok(telemetry(51_000, 118_000, 0)), Some(limits())),
    );
    assert!(e.software_shutdown);
    let (_, e) = update(
        Some(s),
        sample(Ok(telemetry(51_000, 118_000, 0)), Some(limits())),
    );
    assert!(!e.software_shutdown);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_power_update_folds_samples_and_reports_transitions
);

fn navi31_power_hwmon_reads_limits_and_samples() -> TestResult {
    let snap = Snapshot {
        telemetry: Some(telemetry(51_000, 63_000, 0)),
        limits: Some(limits()),
        protected: true,
        error: None,
        samples: 1,
    };
    assert_eq!(show(Some(&snap), "temp1_input"), "51000\n");
    assert_eq!(show(Some(&snap), "temp2_input"), "63000\n");
    assert_eq!(show(Some(&snap), "temp1_crit"), "100000\n");
    assert_eq!(show(Some(&snap), "temp1_crit_hyst"), "-273150\n");
    assert_eq!(show(Some(&snap), "temp1_emergency"), "105000\n");
    assert_eq!(show(Some(&snap), "fan1_input"), "1350\n");
    assert_eq!(show(Some(&snap), "fan1_max"), "3300\n");
    // Power reads in microwatts, clocks in hertz.
    assert_eq!(show(Some(&snap), "power1_average"), "186000000\n");
    assert_eq!(show(Some(&snap), "power1_cap"), "300000000\n");
    assert_eq!(show(Some(&snap), "power1_cap_default"), "304000000\n");
    assert_eq!(show(Some(&snap), "power1_cap_min"), "273000000\n");
    assert_eq!(show(Some(&snap), "power1_cap_max"), "340000000\n");
    assert_eq!(show(Some(&snap), "freq1_input"), "600000000\n");
    assert_eq!(show(Some(&snap), "freq2_input"), "2000000000\n");
    // Empty until a sample or limits exist: never a fake zero.
    assert_eq!(show(None, "temp1_input"), "");
    assert_eq!(show(None, "power1_cap_min"), "");
    assert!(attributes(true).contains(&"power1_cap_min"));
    assert!(attributes(false).contains(&"temp1_input"));
    // power1_cap writes validate against the board range, in microwatts.
    assert_eq!(power_cap_request(Some(limits()), b"300000000\n"), Ok(300));
    assert_eq!(power_cap_request(Some(limits()), b"273000000"), Ok(273));
    assert_eq!(power_cap_request(Some(limits()), b"340000000"), Ok(340));
    for bad in [&b"272999999"[..], b"341000000", b"0", b"", b"-5"] {
        assert_eq!(
            power_cap_request(Some(limits()), bad),
            Err(FsError::InvalidData)
        );
    }
    assert_eq!(
        power_cap_request(None, b"300000000"),
        Err(FsError::NoDevice)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi31-power",
    navi31_power_hwmon_reads_limits_and_samples
);
