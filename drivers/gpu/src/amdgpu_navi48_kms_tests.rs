use super::*;
use crate::drm::ioctl::{dispatch, mode_to_wire, DrmIoctlResult};
use crate::drm::render_node::DrmFileCtx;
use narf_kernel_test::{kernel_test_in, TestResult};

/// CEA 1920x1080@60: 148.5 MHz, 2200x1125, positive syncs.
fn cea_1080p() -> Timing {
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
/// One output of `kind` with `sink` lit (or none).
fn one<'a>(kind: ConnectorType, sink: Option<Sink<'a>>) -> [Output<'a>; 1] {
    [Output {
        kind,
        sink,
        edid: None,
        offered: &[],
    }]
}
fn lit<'a>(edid: &'a [u8; 128], timing: &'a Timing, offered: &'a [Timing]) -> Option<Sink<'a>> {
    Some(Sink {
        edid,
        timing,
        offered,
    })
}
fn geometry(m: &DrmModeModeInfo) -> [u32; 12] {
    [
        m.clock,
        m.hdisplay.into(),
        m.hsync_start.into(),
        m.hsync_end.into(),
        m.htotal.into(),
        m.vdisplay.into(),
        m.vsync_start.into(),
        m.vsync_end.into(),
        m.vtotal.into(),
        m.vrefresh,
        m.flags,
        m.r#type,
    ]
}

fn navi48_kms_discovery_keeps_disabled_connector_connected() -> TestResult {
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    let edid = [7u8; 128];
    let mut output = Output {
        kind: ConnectorType::DisplayPort,
        sink: None,
        edid: Some(&edid),
        offered: &[],
    };
    let timing = cea_1080p();
    apply(
        &mut card,
        &one(
            ConnectorType::DisplayPort,
            lit(&[1; 128], &timing, &[timing]),
        ),
    );
    card.crtcs[0].primary_fb = Some(7);
    apply(&mut card, &[output]);
    assert_eq!(card.connectors[0].status, ConnectorStatus::Connected);
    assert!(card.connectors[0].modes.is_empty());
    assert!(!card.crtcs[0].enabled && card.crtcs[0].mode.is_none());
    assert!(card.crtcs[0].primary_fb.is_none());
    assert_eq!(
        card.native_output(CONNECTOR).and_then(|n| n.edid),
        Some(edid)
    );
    assert!(!card.accepts_mode(&timing_wire(&cea_1080p())));
    output.edid = None;
    apply(&mut card, &[output]);
    assert_eq!(card.connectors[0].status, ConnectorStatus::Disconnected);
    assert!(card.native_output(CONNECTOR).unwrap().edid.is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_discovery_keeps_disabled_connector_connected
);

fn navi48_kms_admitted_modes_do_not_enable_crtc() -> TestResult {
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    let edid = [7u8; 128];
    let a = cea_1080p();
    let b = Timing {
        pixel_clock_khz: 74_250,
        h_active: 1280,
        h_total: 1650,
        h_front_porch: 110,
        h_sync_width: 40,
        v_active: 720,
        v_total: 750,
        v_front_porch: 5,
        v_sync_width: 5,
        ..a
    };
    let modes = [a, b];
    let mut output = Output {
        kind: ConnectorType::DisplayPort,
        sink: None,
        edid: Some(&edid),
        offered: &modes,
    };
    apply(&mut card, &[output]);
    assert_eq!(card.connectors[0].status, ConnectorStatus::Connected);
    assert!(!card.crtcs[0].enabled && card.crtcs[0].mode.is_none());
    assert!(card.crtcs[0].primary_fb.is_none());
    let mut arg = [0u8; 80];
    arg[48..52].copy_from_slice(&CONNECTOR.to_le_bytes());
    match dispatch(&mut card, 0xA7, &arg, &DrmFileCtx::primary_master()) {
        Ok(DrmIoctlResult::GetConnector(_, offered)) => {
            assert_eq!(offered.len(), 2);
            assert_eq!(offered[0].clock, a.pixel_clock_khz);
            assert_eq!(offered[0].r#type, PREFERRED_DRIVER);
            assert_eq!(offered[1].clock, b.pixel_clock_khz);
            assert_eq!(offered[1].r#type, DRIVER);
        }
        other => panic!("GETCONNECTOR {other:?}"),
    }
    assert!(card.accepts_mode(&timing_wire(&a)) && card.accepts_mode(&timing_wire(&b)));
    let unadmitted = Timing {
        pixel_clock_khz: 297_000,
        ..a
    };
    assert!(!card.accepts_mode(&timing_wire(&unadmitted)));
    // Neither a stale mode list after disconnect nor an explicit ACTIVE=1
    // without a set CRTC mode may make the connector scan out.
    set_crtc_active(&mut card, 0, true);
    assert!(!card.crtcs[0].enabled);
    output.edid = None;
    apply(&mut card, &[output]);
    assert!(card.connectors[0].modes.is_empty());
    assert!(!card.accepts_mode(&timing_wire(&a)));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_admitted_modes_do_not_enable_crtc
);

fn navi48_kms_reports_exact_sink_timing() -> TestResult {
    let w = timing_wire(&cea_1080p());
    if geometry(&w)
        != [
            148_500, 1920, 2008, 2052, 2200, 1080, 1084, 1089, 1125, 60, 5, 0x48,
        ]
        || &w.name[..10] != b"1920x1080\0"
    {
        return TestResult::Fail("1080p wire timing");
    }
    // Negative syncs and a non-integer refresh round to the nearest hertz.
    let t = Timing {
        pixel_clock_khz: 148_352,
        h_sync_positive: false,
        v_sync_positive: false,
        ..cea_1080p()
    };
    let w = timing_wire(&t);
    if w.flags != NHSYNC | NVSYNC || w.vrefresh != 60 {
        return TestResult::Fail("negative syncs / 59.94 Hz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_reports_exact_sink_timing
);

fn navi48_kms_publishes_connector_edid_and_refuses_other_modes() -> TestResult {
    let mut edid = [0u8; 128];
    edid[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    edid[127] = 0x5a;
    let t = cea_1080p();
    let wire = timing_wire(&t);
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    let ts = [t];
    apply(
        &mut card,
        &one(ConnectorType::DisplayPort, lit(&edid, &t, &ts)),
    );
    apply(
        &mut card,
        &one(ConnectorType::DisplayPort, lit(&edid, &t, &ts)),
    ); // idempotent topology
    if (card.crtcs.len(), card.encoders.len(), card.connectors.len()) != (1, 1, 1) {
        return TestResult::Fail("topology duplicated");
    }
    let c = &card.connectors[0];
    let mode = Mode {
        width: 1920,
        height: 1080,
        refresh_hz: 60,
        bpp: 32,
    };
    if c.status != ConnectorStatus::Connected
        || c.connector_type != ConnectorType::DisplayPort
        || c.modes != [mode]
        || card.crtcs[0].mode != Some(mode)
        || card.native_output(CONNECTOR).and_then(|n| n.edid) != Some(edid)
        || geometry(&card.mode_wire(&mode)) != geometry(&wire)
    {
        return TestResult::Fail("lit connector");
    }
    // GETCONNECTOR returns the real timing, not the synthesized one.
    let mut arg = [0u8; 80];
    arg[48..52].copy_from_slice(&CONNECTOR.to_le_bytes());
    match dispatch(&mut card, 0xA7, &arg, &DrmFileCtx::primary_master()) {
        Ok(DrmIoctlResult::GetConnector(_, modes))
            if modes.len() == 1 && geometry(&modes[0]) == geometry(&wire) => {}
        _ => return TestResult::Fail("GETCONNECTOR timing"),
    }
    // Only the published timing may be set; the synthesized one may not.
    if !card.accepts_mode(&wire) || card.accepts_mode(&mode_to_wire(&mode)) {
        return TestResult::Fail("SETCRTC mode gate");
    }
    // Atomic MODE_ID blobs get the same gate as SETCRTC.
    let blob = |m: &DrmModeModeInfo| {
        let mut b = alloc::vec::Vec::with_capacity(68);
        b.extend_from_slice(&m.clock.to_ne_bytes());
        for v in [
            m.hdisplay,
            m.hsync_start,
            m.hsync_end,
            m.htotal,
            m.hskew,
            m.vdisplay,
            m.vsync_start,
            m.vsync_end,
            m.vtotal,
            m.vscan,
        ] {
            b.extend_from_slice(&v.to_ne_bytes());
        }
        for v in [m.vrefresh, m.flags, m.r#type] {
            b.extend_from_slice(&v.to_ne_bytes());
        }
        b.extend_from_slice(&m.name);
        b
    };
    if !card.accepts_mode_blob(&blob(&wire))
        || card.accepts_mode_blob(&blob(&mode_to_wire(&mode)))
        || card.accepts_mode_blob(&blob(&wire)[..67])
    {
        return TestResult::Fail("atomic MODE_ID gate");
    }
    // A DRM-driven disable switches the CRTC off and keeps the sink.
    set_crtc_active(&mut card, 0, false);
    if card.crtcs[0].enabled
        || card.crtcs[0].mode != Some(mode)
        || card.connectors[0].status != ConnectorStatus::Connected
        || card.connectors[0].modes != [mode]
    {
        return TestResult::Fail("DRM disable");
    }
    set_crtc_active(&mut card, 0, true);
    if !card.crtcs[0].enabled {
        return TestResult::Fail("DRM re-enable");
    }
    // Unplugged: disconnected, no modes or EDID, and no mode accepted.
    card.crtcs[0].primary_fb = Some(7);
    apply(&mut card, &one(ConnectorType::DisplayPort, None));
    let c = &card.connectors[0];
    if c.status != ConnectorStatus::Disconnected
        || !c.modes.is_empty()
        || card.crtcs[0].mode.is_some()
        || card.crtcs[0].enabled
        || card.crtcs[0].primary_fb.is_some()
        || card
            .native_output(CONNECTOR)
            .is_none_or(|n| n.edid.is_some())
        || card.accepts_mode(&wire)
    {
        return TestResult::Fail("unplugged connector");
    }
    // Nothing to switch on without a mode.
    set_crtc_active(&mut card, 0, true);
    if card.crtcs[0].enabled {
        return TestResult::Fail("enabled without a mode");
    }
    // Cards without native outputs keep accepting any mode.
    if !Card::new("bochs", "", (1, 0, 0)).accepts_mode(&mode_to_wire(&mode)) {
        return TestResult::Fail("non-native card gated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_publishes_connector_edid_and_refuses_other_modes
);

fn navi48_kms_offers_every_switchable_mode_with_the_running_one_current() -> TestResult {
    let edid = [0u8; 128];
    let p = cea_1080p();
    let small = Timing {
        pixel_clock_khz: 74_250,
        h_active: 1280,
        h_total: 1650,
        h_front_porch: 110,
        h_sync_width: 40,
        v_active: 720,
        v_total: 750,
        v_front_porch: 5,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    };
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    // Running 720p, the EDID preferring 1080p.
    let offered = [p, small];
    apply(
        &mut card,
        &one(ConnectorType::DisplayPort, lit(&edid, &small, &offered)),
    );
    let m = |t: &Timing| Mode {
        width: t.h_active,
        height: t.v_active,
        refresh_hz: 60,
        bpp: 32,
    };
    if card.connectors[0].modes != [m(&small), m(&p)] || card.crtcs[0].mode != Some(m(&small)) {
        return TestResult::Fail("offered modes");
    }
    let timings = &card.native_output(CONNECTOR).unwrap().timings;
    // PREFERRED marks the EDID's preferred timing only.
    if timings.len() != 2
        || geometry(&timings[0])[..11] != geometry(&timing_wire(&small))[..11]
        || timings[0].r#type & 0x8 != 0
        || timings[1].r#type & 0x8 == 0
    {
        return TestResult::Fail("native timings and preferred flag");
    }
    if !card.accepts_mode(&timing_wire(&p)) || !card.accepts_mode(&timing_wire(&small)) {
        return TestResult::Fail("every offered timing accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_offers_every_switchable_mode_with_the_running_one_current
);

fn navi48_kms_reports_hdmi_connectors_and_keeps_the_type_when_unplugged() -> TestResult {
    let edid = [0u8; 128];
    let t = cea_1080p();
    let ts = [t];
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    apply(&mut card, &one(ConnectorType::HdmiA, lit(&edid, &t, &ts)));
    if card.connectors[0].connector_type != ConnectorType::HdmiA
        || card.connectors[0].status != ConnectorStatus::Connected
    {
        return TestResult::Fail("HDMI connector");
    }
    apply(&mut card, &one(ConnectorType::HdmiA, None));
    if card.connectors[0].connector_type != ConnectorType::HdmiA
        || card.connectors[0].status != ConnectorStatus::Disconnected
    {
        return TestResult::Fail("unplugged HDMI connector");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_reports_hdmi_connectors_and_keeps_the_type_when_unplugged
);

/// Every lightable port is an output with its own CRTC (its pipe), encoder
/// and connector; output 0 keeps ids 1, 2, 3 and output k adds 3k. Each
/// encoder drives only its CRTC, each connector carries its own sink and
/// modes, and the vblank source maps each CRTC to its display.
fn navi48_kms_publishes_an_output_per_port() -> TestResult {
    let edid_a = [1u8; 128];
    let edid_c = [3u8; 128];
    let a = cea_1080p();
    let c = Timing {
        pixel_clock_khz: 74_250,
        h_active: 1280,
        h_total: 1650,
        h_front_porch: 110,
        h_sync_width: 40,
        v_active: 720,
        v_total: 750,
        v_front_porch: 5,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    };
    let (ta, tc) = ([a], [c]);
    let outputs = [
        Output {
            edid: None,
            offered: &[],
            kind: ConnectorType::DisplayPort,
            sink: lit(&edid_a, &a, &ta),
        },
        Output {
            edid: None,
            offered: &[],
            kind: ConnectorType::DisplayPort,
            sink: None,
        },
        Output {
            edid: None,
            offered: &[],
            kind: ConnectorType::HdmiA,
            sink: lit(&edid_c, &c, &tc),
        },
    ];
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    apply(&mut card, &outputs);
    let ids = |k: usize| (crtc_id(k), encoder_id(k), connector_id(k));
    if (ids(0), ids(1), ids(2)) != ((1, 2, 3), (4, 5, 6), (7, 8, 9))
        || card
            .crtcs
            .iter()
            .map(|c| c.id)
            .collect::<alloc::vec::Vec<_>>()
            != [1, 4, 7]
    {
        return TestResult::Fail("object ids");
    }
    for (k, e) in card.encoders.iter().enumerate() {
        if e.possible_crtcs != 1 << k || e.crtc_id != Some(crtc_id(k)) {
            return TestResult::Fail("encoder bound to its CRTC");
        }
    }
    let status: alloc::vec::Vec<_> = card.connectors.iter().map(|c| c.status).collect();
    let types: alloc::vec::Vec<_> = card
        .connectors
        .iter()
        .map(|c| (c.connector_type, c.connector_type_id))
        .collect();
    if status
        != [
            ConnectorStatus::Connected,
            ConnectorStatus::Disconnected,
            ConnectorStatus::Connected,
        ]
        || types
            != [
                (ConnectorType::DisplayPort, 1),
                (ConnectorType::DisplayPort, 2),
                (ConnectorType::HdmiA, 1),
            ]
    {
        return TestResult::Fail("connector status and types");
    }
    if card.crtcs[0].mode.map(|m| m.width) != Some(1920)
        || card.crtcs[1].enabled
        || card.crtcs[2].mode.map(|m| m.width) != Some(1280)
        || card.native_output(connector_id(0)).and_then(|n| n.edid) != Some(edid_a)
        || card.native_output(connector_id(2)).and_then(|n| n.edid) != Some(edid_c)
        || card
            .native_output(connector_id(1))
            .is_none_or(|n| n.edid.is_some())
    {
        return TestResult::Fail("per-output sinks");
    }
    // Switching one CRTC off leaves the others.
    set_crtc_active(&mut card, 2, false);
    if card.crtcs[2].enabled || !card.crtcs[0].enabled {
        return TestResult::Fail("one CRTC off");
    }
    if [1, 4, 7, 10].map(crtc_display) != [Some(0), Some(1), Some(2), Some(3)]
        || [0, 2, 3, 13].map(crtc_display) != [None; 4]
        || card.vblank_source.is_none()
        || card.plane_formats.is_none()
        || !card.native_atomic
    {
        return TestResult::Fail("CRTC to display");
    }
    // The same outputs again keep the topology (and open clients' state).
    card.crtcs[0].primary_fb = Some(5);
    apply(&mut card, &outputs);
    if card.crtcs.len() != 3 || card.crtcs[0].primary_fb != Some(5) {
        return TestResult::Fail("topology rebuilt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_publishes_an_output_per_port
);

/// The primary plane lists amdgpu_dm_plane_get_plane_formats' DCN4.0.1
/// order (rgb_formats, then the FP16 formats) less RGBA8888, the 16-bit
/// UNORM orders, NV12 and P010, and every card it publishes carries it.
fn navi48_kms_plane_formats_follow_amdgpu_dm() -> TestResult {
    let want = [
        *b"XR24", *b"AR24", *b"XR30", *b"XB30", *b"AR30", *b"AB30", *b"XB24", *b"AB24", *b"RG16",
        *b"XR4H", *b"AR4H", *b"XB4H", *b"AB4H",
    ]
    .map(u32::from_le_bytes);
    if PLANE_FORMATS != want {
        return TestResult::Fail("plane format list");
    }
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    apply(&mut card, &[]);
    if card.plane_formats != Some(&PLANE_FORMATS[..]) {
        return TestResult::Fail("published plane formats");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_plane_formats_follow_amdgpu_dm
);

/// Routed outputs: four CRTCs, one encoder per connector able to drive
/// any CRTC, an MST end device's connector past the board ones. A
/// connector shows its routed CRTC's sink; an unrouted one its discovered
/// EDID and admitted timings. Rerouting keeps every object id.
fn navi48_kms_routes_connectors_to_any_crtc() -> TestResult {
    let t = cea_1080p();
    let edid_a = [0xa; 128];
    let edid_m = [0xe; 128];
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    let crtcs = [None, None, lit(&edid_m, &t, &[]), None];
    let mut connectors = [
        RoutedConnector {
            index: 0,
            kind: ConnectorType::DisplayPort,
            edid: None,
            offered: &[],
            crtc: None,
            possible_crtcs: 0xf,
        },
        RoutedConnector {
            index: 1,
            kind: ConnectorType::HdmiA,
            edid: Some(&edid_a),
            offered: core::slice::from_ref(&t),
            crtc: None,
            possible_crtcs: 0xf,
        },
        RoutedConnector {
            index: 33,
            kind: ConnectorType::DisplayPort,
            edid: Some(&edid_m),
            offered: &[],
            crtc: Some(2),
            possible_crtcs: 0xf,
        },
    ];
    apply_routed(&mut card, &crtcs, &connectors);
    assert_eq!(
        (card.crtcs.len(), card.encoders.len(), card.connectors.len()),
        (4, 3, 3)
    );
    let ids: alloc::vec::Vec<u32> = card.connectors.iter().map(|c| c.id).collect();
    assert_eq!(ids, [3, 6, 102]);
    assert_eq!(connector_index(102), Some(33));
    assert!(card.encoders.iter().all(|e| e.possible_crtcs == 0xf));
    let encoder_crtc = |card: &Card, i: usize| card.encoder(encoder_id(i)).unwrap().crtc_id;
    assert_eq!(encoder_crtc(&card, 33), Some(crtc_id(2)));
    assert_eq!(encoder_crtc(&card, 1), None);
    assert!(card.crtc(crtc_id(2)).unwrap().mode.is_some());
    assert!(card.crtc(crtc_id(0)).unwrap().mode.is_none());
    let mst = card.connector(102).unwrap();
    assert_eq!(mst.status, ConnectorStatus::Connected);
    assert_eq!(mst.modes.len(), 1);
    assert_eq!(card.native_output(102).and_then(|n| n.edid), Some(edid_m));
    // Dark but discovered: connected with its admitted timing.
    let hdmi = card.connector(6).unwrap();
    assert_eq!(hdmi.status, ConnectorStatus::Connected);
    assert_eq!(hdmi.connector_type_id, 1);
    assert_eq!(hdmi.modes.len(), 1);
    assert_eq!(
        card.connector(3).unwrap().status,
        ConnectorStatus::Disconnected
    );
    // Route the HDMI sink to CRTC 0 beside the end device: ids stay, the
    // framebuffer binding on the untouched CRTC survives.
    card.crtc_mut(crtc_id(2)).unwrap().primary_fb = Some(7);
    connectors[1].crtc = Some(0);
    let crtcs = [lit(&edid_a, &t, &[]), None, lit(&edid_m, &t, &[]), None];
    apply_routed(&mut card, &crtcs, &connectors);
    let after: alloc::vec::Vec<u32> = card.connectors.iter().map(|c| c.id).collect();
    assert_eq!(after, [3, 6, 102]);
    assert_eq!(encoder_crtc(&card, 1), Some(crtc_id(0)));
    assert!(card.crtc(crtc_id(0)).unwrap().mode.is_some());
    assert_eq!(card.crtc(crtc_id(2)).unwrap().primary_fb, Some(7));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_routes_connectors_to_any_crtc
);

/// amdgpu_dm's VRR properties on the native card: every connector carries
/// the immutable "vrr_capable" (its sink's FreeSync capability) and every
/// CRTC "VRR_ENABLED", whose committed value survives republication and
/// topology changes for CRTCs that remain. `apply_routed` (Navi22, tests)
/// attaches neither.
fn navi48_kms_publishes_vrr_properties() -> TestResult {
    let t = cea_1080p();
    let edid = [0xa; 128];
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    let crtcs = [lit(&edid, &t, &[]), None, None, None];
    let connectors = [
        RoutedConnector {
            index: 0,
            kind: ConnectorType::DisplayPort,
            edid: Some(&edid),
            offered: &[],
            crtc: Some(0),
            possible_crtcs: 0xf,
        },
        RoutedConnector {
            index: 1,
            kind: ConnectorType::HdmiA,
            edid: None,
            offered: &[],
            crtc: None,
            possible_crtcs: 0xf,
        },
    ];
    apply_routed_vrr(&mut card, &crtcs, &connectors, Some(&[true]));
    let capable = |card: &Card, n: usize| {
        card.native_output(connector_id(n))
            .and_then(|o| o.vrr_capable)
    };
    if capable(&card, 0) != Some(true) || capable(&card, 1) != Some(false) {
        return TestResult::Fail("vrr_capable values");
    }
    let ids: alloc::vec::Vec<(u32, bool)> = (0..4).map(|k| (crtc_id(k), false)).collect();
    if card.vrr_enabled != ids {
        return TestResult::Fail("VRR_ENABLED on every CRTC");
    }
    // A committed value survives republishing the same and a smaller
    // topology; a CRTC that goes away drops it.
    card.vrr_enabled[0].1 = true;
    card.vrr_enabled[3].1 = true;
    apply_routed_vrr(&mut card, &crtcs, &connectors, Some(&[false, false]));
    if card.vrr_enabled[0] != (crtc_id(0), true) || capable(&card, 0) != Some(false) {
        return TestResult::Fail("republished");
    }
    apply_routed_vrr(&mut card, &crtcs[..2], &connectors, Some(&[true, true]));
    if card.vrr_enabled != [(crtc_id(0), true), (crtc_id(1), false)] {
        return TestResult::Fail("smaller topology");
    }
    apply_routed(&mut card, &crtcs, &connectors);
    if !card.vrr_enabled.is_empty() || capable(&card, 0).is_some() {
        return TestResult::Fail("attached without VRR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_publishes_vrr_properties
);
