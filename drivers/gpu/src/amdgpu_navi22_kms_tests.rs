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

/// Distinct DCN30 timings can round to the same Mode (size and integer Hz).
/// GETCONNECTOR must still offer the exact timings accepted by SETCRTC,
/// rather than replacing the whole list with synthesized timings.
fn navi22_kms_duplicate_geometry_keeps_exact_connector_timings() -> TestResult {
    use crate::drm::ioctl::{dispatch, DrmIoctlResult};
    use crate::drm::render_node::DrmFileCtx;
    let mut card = Card::new("amdgpu", "DCN30 timing fixture", (3, 60, 0));
    let preferred = Timing {
        pixel_clock_khz: 533_250,
        h_active: 3840,
        h_total: 4000,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 2160,
        v_total: 2222,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: false,
    };
    let alternate = Timing {
        pixel_clock_khz: 594_000,
        h_total: 4400,
        h_front_porch: 176,
        h_sync_width: 88,
        v_total: 2250,
        v_front_porch: 8,
        v_sync_width: 10,
        ..preferred
    };
    let offered = [preferred, alternate];
    let edid = [1; 128];
    let crtcs = [Some(crate::amdgpu_navi48_kms::Sink {
        edid: &edid,
        timing: &preferred,
        offered: &offered,
    })];
    let connectors = [crate::amdgpu_navi48_kms::RoutedConnector {
        index: 3,
        kind: ConnectorType::HdmiA,
        edid: Some(&edid),
        offered: &offered,
        crtc: Some(0),
        possible_crtcs: 1,
    }];
    apply_card(&mut card, &crtcs, &connectors);
    if card.connectors[0].modes.len() != 1 || card.native[0].timings.len() != 2 {
        return TestResult::Fail("fixture does not reproduce rounded-mode deduplication");
    }
    let id = card.connectors[0].id;
    let mut request = [0u8; 80];
    request[48..52].copy_from_slice(&id.to_le_bytes());
    let Ok(DrmIoctlResult::GetConnector(info, modes)) = dispatch(
        &mut card,
        0xc050_64a7,
        &request,
        &DrmFileCtx::primary_master(),
    ) else {
        return TestResult::Fail("GETCONNECTOR of the DCN30 fixture failed");
    };
    if info.count_modes != 2 || modes.len() != 2 {
        return TestResult::Fail("GETCONNECTOR lost exact timings sharing rounded geometry");
    }
    for (wire, timing) in modes.iter().zip(offered) {
        let expected = crate::amdgpu_navi48_kms::timing_wire(&timing);
        if wire.clock != expected.clock
            || wire.hdisplay != expected.hdisplay
            || wire.hsync_start != expected.hsync_start
            || wire.hsync_end != expected.hsync_end
            || wire.htotal != expected.htotal
            || wire.vdisplay != expected.vdisplay
            || wire.vsync_start != expected.vsync_start
            || wire.vsync_end != expected.vsync_end
            || wire.vtotal != expected.vtotal
            || wire.flags != expected.flags
            || !card.accepts_mode(wire)
        {
            return TestResult::Fail("GETCONNECTOR offered a synthesized or rejected timing");
        }
    }
    let synthesized = crate::drm::ioctl::mode_to_wire(&card.connectors[0].modes[0]);
    if card.accepts_mode(&synthesized) {
        return TestResult::Fail("fixture unexpectedly accepts the old synthesized timing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/drm/native_modes",
    navi22_kms_duplicate_geometry_keeps_exact_connector_timings
);

fn navi22_kms_publication_excludes_rdna4_only_planes_and_modifiers() -> TestResult {
    let mut card = Card::new("amdgpu", "DCN30 publication fixture", (3, 60, 0));
    let edid = [1; 128];
    let timing = hd();
    let offered = [timing];
    let crtcs = [Some(crate::amdgpu_navi48_kms::Sink {
        edid: &edid,
        timing: &timing,
        offered: &offered,
    })];
    let connectors = [crate::amdgpu_navi48_kms::RoutedConnector {
        index: 3,
        kind: ConnectorType::HdmiA,
        edid: Some(&edid),
        offered: &offered,
        crtc: Some(0),
        possible_crtcs: 1,
    }];
    apply_card(&mut card, &crtcs, &connectors);
    if card.gfx12_modifiers || !card.native_planes.is_empty() || card.overlay_formats.is_some() {
        return TestResult::Fail("DCN30 advertised RDNA4-only KMS operations");
    }
    if !card.native_atomic
        || card.plane_formats != Some(&PLANE_FORMATS[..])
        || !crate::amdgpu_native_kms::linear_gem_card(&card)
    {
        return TestResult::Fail("DCN30 linear primary/atomic capability missing");
    }
    let Some(blob) = crate::drm_native_planes::in_formats_blob(
        &card,
        crate::drm_native_planes::in_formats_blob_id(0x40),
    ) else {
        return TestResult::Fail("DCN30 primary has no explicit LINEAR format blob");
    };
    let word = |i| u32::from_le_bytes(blob[i..i + 4].try_into().unwrap());
    let modifiers = word(20) as usize;
    if word(8) != 2 || word(16) != 1 || blob[modifiers + 16..modifiers + 24] != [0u8; 8] {
        return TestResult::Fail("DCN30 format blob advertises a tiled layout");
    }
    let native = card
        .native
        .iter_mut()
        .find(|n| n.connector == crate::amdgpu_navi48_kms::connector_id(3))
        .unwrap();
    if native.colorspace != Some(0)
        || native.hdr_output_metadata != Some(0)
        || native.max_bpc.is_none()
        || native.color_format != Some(crate::amdgpu_hdr::ColorFormat::Auto)
    {
        return TestResult::Fail("HDMI output controls absent");
    }
    native.max_bpc = Some(10);
    native.colorspace = Some(crate::amdgpu_hdr::DRM_MODE_COLORIMETRY_BT2020_RGB);
    native.color_format = Some(crate::amdgpu_hdr::ColorFormat::Ycbcr422);
    // Re-publishing keeps committed controls and excludes DCN401's planes.
    apply_card(&mut card, &crtcs, &connectors);
    if card.gfx12_modifiers
        || !card.native_planes.is_empty()
        || card.native[0].max_bpc != Some(10)
        || card.native[0].colorspace != Some(crate::amdgpu_hdr::DRM_MODE_COLORIMETRY_BT2020_RGB)
        || card.native[0].color_format != Some(crate::amdgpu_hdr::ColorFormat::Ycbcr422)
    {
        return TestResult::Fail(
            "republication changed the DCN30 plane ABI or committed output state",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_kms_publication_excludes_rdna4_only_planes_and_modifiers
);

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
        dcn_revision: 0,
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
        || !d.watermarks
        || d.deep_sleep_dcefclk
        || d.min_uclk_mhz != 1000
        || d.min_fclk_mhz != 1200
        || u32::from(d.min_dcefclk_mhz) != plan.clocks.dcfclk_khz / 1000
    {
        return TestResult::Fail("admission fields");
    }
    if display_admission(&a, 0).dram_clock_change || display_admission(&a, 0).watermarks {
        return TestResult::Fail("retired pipes claim a p-state guarantee");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_display_admission_reports_only_what_dml30_proved
);

/// DP sinks are lightable with the offers their link admits (the whole
/// sink, DPCD included, reaches the offer function); HDMI routes first,
/// then the first DP sink; DRM may route any board port.
fn navi22_kms_dp_sinks_offer_their_link_modes() -> TestResult {
    let mut r = reports(false, 1);
    let dp = |edid| {
        Detection::Connected(Sink {
            edid: vec![edid; 128],
            preferred: None,
            hdmi: false,
            dpcd: Some([0x12, 0x14, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        })
    };
    r[1].detection = dp(5);
    r[2].detection = dp(6);
    let mut k = Kms::new();
    // Only a DP sink with receiver caps gets modes; the link bounds them.
    k.reconcile_sinks(&r, |_, sink| {
        Some(if sink.dpcd.is_some() {
            vec![xga()]
        } else {
            vec![]
        })
    });
    k.assign_route();
    if !k.connectors[1].lightable() || k.connectors[1].modes != [xga()] || k.crtc.route != Some(1) {
        return TestResult::Fail("DP sink not routed with its link modes");
    }
    let wire = crate::amdgpu_navi48_kms::timing_wire(&xga());
    if k.find_mode(None, &wire) != Some(xga())
        || k.find_mode(None, &crate::amdgpu_navi48_kms::timing_wire(&hd()))
            .is_some()
    {
        return TestResult::Fail("DP offers");
    }
    // An HDMI sink is preferred when both are connected.
    let mut both = r.clone();
    both[3] = reports(true, 1).pop().unwrap();
    let mut k = Kms::new();
    k.reconcile_sinks(&both, |_, _| Some(vec![hd(), xga()]));
    k.assign_route();
    if k.crtc.route != Some(3) {
        return TestResult::Fail("HDMI not preferred");
    }
    // A sink without admitted modes on its link is not lightable.
    let mut k = Kms::new();
    k.reconcile_sinks(&r, |_, _| Some(vec![]));
    k.assign_route();
    if k.connectors[1].lightable() || k.crtc.route.is_some() {
        return TestResult::Fail("DP sink lit without modes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_kms_dp_sinks_offer_their_link_modes
);

fn navi22_kms_secondary_crtcs_light_as_one_context() -> TestResult {
    let mut r = reports(true, 1);
    r[0].detection = Detection::Connected(Sink {
        edid: vec![2; 128],
        preferred: None,
        hdmi: false,
        dpcd: None,
    });
    let mut k = Kms::new();
    k.reconcile(&r, admitted);
    // Without the opt-in only CRTC 0 routes itself: no context.
    k.assign_route();
    if k.crtc.route != Some(3)
        || k.secondary.iter().any(|c| c.route.is_some())
        || k.next_group(None) != GroupAction::Nothing
    {
        return TestResult::Fail("automatic secondary routing without the opt-in");
    }
    // With it, the next free CRTC takes DP-1; CRTC 0 keeps HDMI.
    set_auto_multi(true);
    k.assign_route();
    set_auto_multi(false);
    if k.secondary[0].route != Some(0) || k.crtc_of(0) != Some(1) || k.crtc_of(3) != Some(0) {
        return TestResult::Fail("automatic secondary route");
    }
    let both = vec![(0, 3, None), (1, 0, None)];
    if k.next_group(None) != GroupAction::Light(both.clone()) {
        return TestResult::Fail("two wanted CRTCs not lit together");
    }
    // A failed attempt is not retried until something changes.
    k.attempted_group = Some(both.iter().map(|t| (t.1, t.2)).collect());
    if k.next_group(None) != GroupAction::Nothing {
        return TestResult::Fail("failed context retried");
    }
    let lit = [(0, 3, hd()), (1, 0, hd())];
    if k.next_group(Some(&lit)) != GroupAction::Nothing {
        return TestResult::Fail("running context relit");
    }
    // A new mode on one CRTC relights the whole context; CRTC 1 off leaves
    // CRTC 0 to the single-pipe owner.
    k.secondary[0].requested = Some(xga());
    if k.next_group(Some(&lit)) != GroupAction::Unlight {
        return TestResult::Fail("mode change kept the context");
    }
    k.secondary[0].requested = None;
    k.secondary[0].active = false;
    if k.next_group(Some(&lit)) != GroupAction::Unlight
        || k.next_group(None) != GroupAction::Nothing
    {
        return TestResult::Fail("context kept without a secondary");
    }
    // Each CRTC publishes only its own shown sink.
    k.secondary[0].active = true;
    k.secondary[0].shown = Some(([2; 128], hd(), vec![hd()]));
    if k.published_at(1).map(|s| s.1) != Some(hd()) || k.published_at(2).is_some() {
        return TestResult::Fail("per-CRTC publication");
    }
    // An unplugged secondary sink drops its automatic route.
    k.reconcile(&reports(true, 1), admitted);
    k.assign_route();
    if k.secondary[0].route.is_some() {
        return TestResult::Fail("route kept to an unplugged sink");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_kms_secondary_crtcs_light_as_one_context
);

fn navi22_kms_connector_color_requests_converge_and_survive_reprobe() -> TestResult {
    use crate::amdgpu_hdr::{ColorFormat, DRM_MODE_COLORIMETRY_BT2020_RGB};
    use crate::amdgpu_native_kms::ConnectorColorRequest;
    let mut k = Kms::new();
    let r = reports(true, 1);
    k.reconcile(&r, admitted);
    k.assign_route();
    let connector = crate::amdgpu_navi48_kms::connector_id(3);
    let mut color = ConnectorColorRequest {
        connector,
        color_format: ColorFormat::Rgb,
        colorspace: DRM_MODE_COLORIMETRY_BT2020_RGB,
        hdr_output_metadata: Some(vec![0; 32]),
    };
    if !k.set_max_bpc(connector, 10)
        || !k.set_color(&color)
        || k.next(Some((3, hd()))) != Action::Unlight
    {
        return TestResult::Fail("color request never reached convergence");
    }
    k.connectors[3].shown_output = k.connectors[3].output;
    if k.next(Some((3, hd()))) != Action::Nothing {
        return TestResult::Fail("applied state keeps relighting");
    }
    color.hdr_output_metadata.as_mut().unwrap()[26] = 1;
    if !k.set_color(&color)
        || k.next(Some((3, hd()))) != Action::Nothing
        || k.connectors[3].shown_output == k.connectors[3].output
    {
        return TestResult::Fail("metadata-only update causes a modeset or loses pending state");
    }
    let old = k.connectors[3].output;
    k.reconcile(&r, admitted);
    if k.connectors[3].output != old || k.connectors[3].shown_output == old {
        return TestResult::Fail("reprobe erased requested or applied state");
    }
    color.hdr_output_metadata = None;
    if !k.set_color(&color) || k.next(Some((3, hd()))) != Action::Unlight {
        return TestResult::Fail("HDR exit did not relight");
    }
    let before = k.connectors[3].output;
    color.hdr_output_metadata = Some(vec![0; 31]);
    if k.set_color(&color) || k.set_max_bpc(connector, 7) || k.connectors[3].output != before {
        return TestResult::Fail("invalid state mutated connector");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_kms_connector_color_requests_converge_and_survive_reprobe
);

fn navi22_kms_hdmi_format_check_is_exact_and_side_effect_free() -> TestResult {
    use crate::amdgpu_dcn30_hdmi::tests::{edid, vsdb, DTD_1080P};
    use crate::amdgpu_hdr::ColorFormat;
    use crate::amdgpu_native_kms::{OutputFormatRequest, OutputRoute};
    let mut r = reports(true, 1);
    let Detection::Connected(sink) = &mut r[3].detection else {
        return TestResult::Fail("fixture");
    };
    sink.edid = edid(DTD_1080P, &[vsdb(0, 68)]);
    crate::amdgpu_dcn30_hdmi::tests::cta_byte(&mut sink.edid, 131, 0x10);
    let mut k = Kms::new();
    k.reconcile(&r, admitted);
    k.assign_route();
    let connector = crate::amdgpu_navi48_kms::connector_id(3);
    let request = OutputFormatRequest {
        display: 0,
        connector,
        color_format: ColorFormat::Ycbcr422,
        mode: Some(crate::amdgpu_navi48_kms::timing_wire(&hd())),
        max_bpc: Some(12),
        planes: None,
    };
    let route = OutputRoute {
        display: 0,
        connector,
        mode: request.mode,
        planes: None,
    };
    let before = k.connectors[3].clone();
    if !k.formats_supported(&[request], &[route]) || k.connectors[3] != before {
        return TestResult::Fail("valid TEST_ONLY changed state or failed");
    }
    if k.formats_supported(
        &[OutputFormatRequest {
            color_format: ColorFormat::Ycbcr444,
            ..request
        }],
        &[route],
    ) || k.formats_supported(&[request], &[route, route])
        || k.formats_supported(
            &[OutputFormatRequest {
                max_bpc: Some(7),
                ..request
            }],
            &[route],
        )
    {
        return TestResult::Fail("invalid explicit format/routing/depth admitted");
    }
    k.connectors[3].hdmi_limits.max_phy_khz = 100_000;
    if k.formats_supported(&[request], &[route]) {
        return TestResult::Fail("immutable board PHY bound ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    navi22_kms_hdmi_format_check_is_exact_and_side_effect_free
);
