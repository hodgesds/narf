use super::*;
use crate::amdgpu_dcn_inventory::{Connector as Kind, Path};
use crate::amdgpu_navi22_display::Sink;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn hd() -> Timing {
    Timing {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        h_front_porch: 88,
        h_sync_width: 44,
        v_active: 1080,
        v_total: 1125,
        v_front_porch: 4,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}
fn xga() -> Timing {
    Timing {
        pixel_clock_khz: 65_000,
        h_active: 1024,
        h_total: 1344,
        h_front_porch: 24,
        h_sync_width: 136,
        v_active: 768,
        v_total: 806,
        v_front_porch: 3,
        v_sync_width: 6,
        h_sync_positive: false,
        v_sync_positive: false,
    }
}
fn port(kind: Kind, signal: Signal, line: u8) -> Port {
    Port {
        path: Path {
            connector: kind,
            connector_instance: line + 1,
            transmitter: line,
            aux: Some(line),
            hpd: line + 1,
            device_tag: 0,
            max_speed_mhz: 0,
        },
        signal,
        line,
        hpd: Some(line),
    }
}
/// The RX 6750 XT's board: DP-1..3 then HDMI-A-1.
fn reports(hdmi: bool, edid: u8) -> Vec<Report> {
    let mut out: Vec<Report> = (0..3)
        .map(|n| Report {
            connector: port(Kind::DisplayPort, Signal::DisplayPort, n),
            detection: Detection::Disconnected,
        })
        .collect();
    out.push(Report {
        connector: port(Kind::HdmiTypeA, Signal::Hdmi, 3),
        detection: if hdmi {
            Detection::Connected(Sink {
                edid: vec![edid; 128],
                preferred: None,
                hdmi: true,
                dpcd: None,
            })
        } else {
            Detection::Disconnected
        },
    });
    out
}
fn admitted(_: &Port, _: &[u8]) -> Option<Vec<Timing>> {
    Some(vec![hd(), xga()])
}

fn navi22_kms_routes_the_hdmi_sink_and_offers_admitted_modes() -> TestResult {
    let mut k = Kms::new();
    k.reconcile(&reports(true, 1), admitted);
    k.assign_route();
    if k.connectors.len() != 4
        || k.connectors[..3]
            .iter()
            .any(|c| c.kind != ConnectorType::DisplayPort || c.lightable())
        || k.connectors[3].kind != ConnectorType::HdmiA
        || k.crtc.route != Some(3)
    {
        return TestResult::Fail("board connectors / automatic route");
    }
    if k.next(None)
        != (Action::Light {
            route: 3,
            want: None,
        })
    {
        return TestResult::Fail("dark CRTC with a sink not lit");
    }
    let wire = crate::amdgpu_navi48_kms::timing_wire(&xga());
    if k.find_mode(None, &wire) != Some(xga()) {
        return TestResult::Fail("admitted mode refused");
    }
    let mut odd = wire;
    odd.htotal += 1;
    if k.find_mode(None, &odd).is_some() || k.find_mode(Some(0), &wire).is_some() {
        return TestResult::Fail("unadmitted mode or undrivable connector accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_kms_routes_the_hdmi_sink_and_offers_admitted_modes
);

fn navi22_kms_converges_requests() -> TestResult {
    let mut k = Kms::new();
    k.reconcile(&reports(true, 1), admitted);
    k.assign_route();
    // Running the preferred mode: nothing to do.
    if k.next(Some((3, hd()))) != Action::Nothing {
        return TestResult::Fail("steady state");
    }
    // Another mode: tear down, then light at it.
    k.crtc.requested = Some(xga());
    if k.next(Some((3, hd()))) != Action::Unlight
        || k.next(None)
            != (Action::Light {
                route: 3,
                want: Some(xga()),
            })
    {
        return TestResult::Fail("mode switch");
    }
    // A failed attempt is not repeated until something changes.
    k.attempted = Some((3, Some(xga())));
    if k.next(None) != Action::Nothing {
        return TestResult::Fail("failed light retried");
    }
    // CRTC off: unlight, and stay dark.
    k.crtc.active = false;
    k.attempted = None;
    if k.next(Some((3, xga()))) != Action::Unlight || k.next(None) != Action::Nothing {
        return TestResult::Fail("CRTC off");
    }
    // Unplug: the route drops and nothing lights.
    k.crtc.active = true;
    k.reconcile(&reports(false, 1), admitted);
    k.assign_route();
    if k.crtc.route.is_some() || k.next(Some((3, hd()))) != Action::Unlight {
        return TestResult::Fail("unplug");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/amdgpu/navi22", navi22_kms_converges_requests);

fn navi22_kms_new_monitor_voids_requested_mode() -> TestResult {
    let mut k = Kms::new();
    k.reconcile(&reports(true, 1), admitted);
    k.assign_route();
    k.crtc.requested = Some(xga());
    k.reconcile(&reports(true, 1), admitted);
    if k.crtc.requested != Some(xga()) {
        return TestResult::Fail("same monitor lost its mode");
    }
    k.reconcile(&reports(true, 2), admitted);
    if k.crtc.requested.is_some() {
        return TestResult::Fail("new monitor inherited the old mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_kms_new_monitor_voids_requested_mode
);

fn navi22_kms_first_light_needs_no_prior_admission() -> TestResult {
    let mut k = Kms::new();
    k.reconcile(&reports(true, 1), |_, _| None);
    k.assign_route();
    if k.crtc.route != Some(3)
        || k.next(None)
            != (Action::Light {
                route: 3,
                want: None,
            })
    {
        return TestResult::Fail("unadmitted HDMI sink not lit at its preferred mode");
    }
    // Nothing is offered to DRM before an admission exists.
    let wire = crate::amdgpu_navi48_kms::timing_wire(&hd());
    if k.find_mode(None, &wire).is_some() {
        return TestResult::Fail("mode offered without admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_kms_first_light_needs_no_prior_admission
);

fn navi22_display_admission_reports_only_what_dml30_proved() -> TestResult {
    use crate::amdgpu_dml30 as dml30;
    let soc = dml30::Soc {
        dcfclk_khz: 1_200_000,
        fabric_khz: 1_200_000,
        socclk_khz: 1_000_000,
        dram_speed_mts: 16_000,
        channels: 12,
        channel_width_bytes: 2,
        max_dispclk_khz: 1_330_000,
        max_dppclk_khz: 1_330_000,
        max_phyclk_khz: 810_000,
        dentist_vco_khz: 3_650_000,
        dchub_refclk_khz: 50_000,
    };
    let config = crate::amdgpu_dml::Config {
        timing: hd(),
        plane: crate::amdgpu_dml::Plane {
            format: crate::amdgpu_dml::Format::Rgb32,
            surface_width: 1920,
            surface_height: 1080,
            viewport_width: 1920,
            viewport_height: 1080,
            pitch: 1920,
            h_taps: 1,
            v_taps: 1,
        },
        dentist_vco_khz: 3_650_000,
        cursors: 0,
    };
    let Ok(plan) = dml30::plan(&config, &soc) else {
        return TestResult::Fail("1080p not admitted");
    };
    let a = crate::amdgpu_navi22_modeset::Admitted {
        soc,
        refclk_khz: 50_000,
        plan,
        offered: vec![hd()],
    };
    let d = display_admission(&a, 1);
    if d.active_streams != 1
        || d.dram_clock_change != (plan.dram_clock_change != dml30::DramClockChange::Unsupported)
        || d.fclk_change
        || d.stutter
        || d.watermarks
        || d.deep_sleep_dcefclk
        || d.min_uclk_mhz != 1000
        || d.min_fclk_mhz != 1200
        || u32::from(d.min_dcefclk_mhz) != plan.clocks.dcfclk_khz / 1000
    {
        return TestResult::Fail("admission fields");
    }
    if display_admission(&a, 0).dram_clock_change {
        return TestResult::Fail("retired pipes claim a p-state guarantee");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_display_admission_reports_only_what_dml30_proved
);
